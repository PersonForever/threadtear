package me.nov.threadtear.execution.cleanup;

import java.util.*;
import java.util.stream.StreamSupport;

import org.objectweb.asm.tree.*;

import me.nov.threadtear.execution.*;
import me.nov.threadtear.util.asm.*;

public class InlineMethods extends Execution {

  public InlineMethods() {
    super(ExecutionCategory.CLEANING, "Inline static methods without invocation",
      "Inline static methods that only return or throw.<br>Can be" +
        " useful for deobfuscating try catch block obfuscation.", ExecutionTag.SHRINK,
      ExecutionTag.RUNNABLE);
  }

  public int inlines;

  @Override
  public boolean execute(Map<String, Clazz> classes, boolean verbose) {
    // Map to hold methods that can potentially be inlined
    HashMap<String, MethodNode> map = new HashMap<>();

    // Step 1: Collect all unnecessary methods that can be inlined
    classes.values().stream()
      .map(c -> c.node)
      .forEach(c -> c.methods.stream()
        .filter(this::isUnnecessary)
        .forEach(m -> {
          String methodKey = c.name + "." + m.name + m.desc;
          map.put(methodKey, m);
          if (verbose) {
            logger.debug("Collected method for inlining: {}", methodKey);
          }
        }));

    logger.info("{} unnecessary methods found that could be inlined", map.size());
    inlines = 0;

    // Step 2: Scan for method invocations and attempt inlining
    classes.values().stream()
      .map(c -> c.node.methods)
      .flatMap(List::stream)
      .forEach(m -> m.instructions.forEach(ain -> {
        if (ain.getOpcode() == INVOKESTATIC) {
          MethodInsnNode min = (MethodInsnNode) ain;
          String invocationKey = min.owner + "." + min.name + min.desc;
          if (verbose) {
            logger.debug("Found method invocation: {}", invocationKey);
          }
          if (map.containsKey(invocationKey)) {
            inlineMethod(m, min, map.get(invocationKey));
            m.maxStack = Math.max(map.get(invocationKey).maxStack, m.maxStack);
            m.maxLocals = Math.max(map.get(invocationKey).maxLocals, m.maxLocals);
            inlines++;
            if (verbose) {
              logger.debug("Inlined method {} in method {} of class {}", invocationKey, m.name, m.desc);
            }
          }
        }
      }));

    logger.info("Inlined {} method references!", inlines);

    // Step 3: Remove all methods identified as unnecessary, regardless of inlining
    // This ensures that any methods not inlined (i.e., not invoked) are deleted
    int deletedUnnecessaryMethods = 0;
    for (Map.Entry<String, MethodNode> entry : map.entrySet()) {
      String key = entry.getKey();
      MethodNode method = entry.getValue();
      String className = key.substring(0, key.lastIndexOf('.'));
      Clazz clazz = classes.get(className);
      if (clazz != null) {
        boolean removed = clazz.node.methods.remove(method);
        if (removed) {
          deletedUnnecessaryMethods++;
          if (verbose) {
            logger.debug("Deleted unnecessary method {} from class {}", key, className);
          }
        }
      }
    }
    logger.info("Deleted {} unnecessary methods!", deletedUnnecessaryMethods);

    // Step 4: Delete junk methods (static methods without RETURN or ATHROW)
    // These methods are already considered unnecessary, but are handled separately for clarity
    int deletedJunkMethods = 0;
    for (Clazz clazz : classes.values()) {
      Iterator<MethodNode> methodIterator = clazz.node.methods.iterator();
      while (methodIterator.hasNext()) {
        MethodNode method = methodIterator.next();
        if (isJunkMethod(method)) {
          methodIterator.remove();
          deletedJunkMethods++;
          if (verbose) {
            logger.debug("Deleted junk method {}.{}{}", clazz.node.name, method.name, method.desc);
          }
        }
      }
    }
    logger.info("Deleted {} junk methods without return or throw instructions!", deletedJunkMethods);

    return true;
  }

  /**
   * Inlines a static method invocation with the method's instructions.
   *
   * @param callerMethod The method containing the invocation.
   * @param min          The method invocation instruction node.
   * @param calleeMethod The method being inlined.
   */
  private void inlineMethod(MethodNode callerMethod, MethodInsnNode min, MethodNode calleeMethod) {
    InsnList copy = Instructions.copy(calleeMethod.instructions);

    // Remove line and frame instructions
    StreamSupport.stream(copy.spliterator(), false)
      .filter(ain -> ain.getType() == AbstractInsnNode.LINE || ain.getType() == AbstractInsnNode.FRAME)
      .forEach(copy::remove);

    boolean hasReturn = removeReturn(copy);
    if (!hasReturn) {
      // Cannot inline methods without RETURN or ATHROW
      logger.error("Cannot inline method {}.{}{} because it has no return or throw instruction.",
        calleeMethod.name, calleeMethod.name, calleeMethod.desc);
      return;
    }

    InsnList fakeVarList = createFakeVarList(calleeMethod);
    copy.insert(fakeVarList);

    // Offset local variables to avoid collisions
    int localVarOffset = callerMethod.maxLocals + 4;
    StreamSupport.stream(copy.spliterator(), false)
      .filter(ain -> ain.getType() == AbstractInsnNode.VAR_INSN)
      .map(ain -> (VarInsnNode) ain)
      .forEach(v -> v.var += localVarOffset);

    callerMethod.instructions.insert(min, copy);
    callerMethod.instructions.remove(min);
  }

  /**
   * Creates an instruction list to load method parameters into local variables.
   *
   * @param method The method whose parameters are being inlined.
   * @return An instruction list for loading parameters.
   */
  private InsnList createFakeVarList(MethodNode method) {
    InsnList fakeVarList = new InsnList();

    LinkedHashMap<Integer, Integer> varTypes = getVarsAndTypesForDesc(method.desc.substring(1, method.desc.indexOf(')')));
    for (Map.Entry<Integer, Integer> entry : varTypes.entrySet()) {
      fakeVarList.insert(new VarInsnNode(entry.getValue(), entry.getKey()));
    }
    return fakeVarList;
  }

  /**
   * Parses method descriptors to determine local variable types and their corresponding store opcodes.
   *
   * @param rawType The raw method descriptor parameters (between '(' and ')').
   * @return A map of local variable indices to their store opcodes.
   */
  public static LinkedHashMap<Integer, Integer> getVarsAndTypesForDesc(String rawType) {
    LinkedHashMap<Integer, Integer> map = new LinkedHashMap<>();
    int var = 0; // Starting index for local variables

    boolean object = false;
    boolean array = false;
    for (int i = 0; i < rawType.length(); i++) {
      char c = rawType.charAt(i);
      if (!object) {
        if (array && c != 'L') {
          map.put(var, ASTORE); // array type is ASTORE
          var++;
          array = false;
          continue;
        }
        switch (c) {
          case 'L':
            array = false;
            map.put(var, ASTORE);
            object = true;
            var++;
            break;
          case 'I':
            map.put(var, ISTORE);
            var++;
            break;
          case 'D':
            map.put(var, DSTORE);
            var += 2;
            break;
          case 'F':
            map.put(var, FSTORE);
            var++;
            break;
          case 'J':
            map.put(var, LSTORE);
            var += 2;
            break;
          case '[':
            array = true;
            break;
          default:
            // Handle other types if necessary
            break;
        }
      } else if (c == ';') {
        object = false;
      }
    }
    return map;
  }

  /**
   * Attempts to remove the return instruction from the method's instructions.
   *
   * @param instructions The instructions to modify.
   * @return true if a RETURN or ATHROW instruction was found and removed, false otherwise.
   */
  private boolean removeReturn(InsnList instructions) {
    int i = instructions.size() - 1;
    while (i >= 0) {
      AbstractInsnNode ain = instructions.get(i);
      int opcode = ain.getOpcode();

      if (opcode == ATHROW) {
        // Keep ATHROW; it's part of the method's behavior
        return true;
      }

      if (opcode == RETURN || opcode == ARETURN || opcode == DRETURN ||
        opcode == FRETURN || opcode == IRETURN || opcode == LRETURN) {
        instructions.remove(ain);
        return true;
      }

      instructions.remove(ain);
      i--;
    }
    // No return or throw instruction found
    return false;
  }

  /**
   * Determines if a method is unnecessary for inlining.
   * A method is unnecessary if it is static, contains at least one RETURN or ATHROW instruction,
   * and does not contain any method invocations or jump instructions.
   *
   * @param m The method node to check.
   * @return true if the method is unnecessary, false otherwise.
   */
  public boolean isUnnecessary(MethodNode m) {
    if (!Access.isStatic(m.access)) {
      return false;
    }

    boolean hasReturnOrThrow = false;
    for (AbstractInsnNode ain : m.instructions) {
      int opcode = ain.getOpcode();
      if (opcode == RETURN || opcode == ARETURN || opcode == DRETURN ||
        opcode == FRETURN || opcode == IRETURN || opcode == LRETURN ||
        opcode == ATHROW) {
        hasReturnOrThrow = true;
      }
      if (isInvocationOrJump(ain)) {
        return false;
      }
    }
    return hasReturnOrThrow;
  }

  /**
   * Determines if a method is a junk method.
   * A junk method is static and contains no RETURN or ATHROW instructions.
   *
   * @param m The method node to check.
   * @return true if the method is junk, false otherwise.
   */
  public boolean isJunkMethod(MethodNode m) {
    // A junk method is static and has no return or throw instruction
    if (!Access.isStatic(m.access)) {
      return false;
    }

    boolean hasReturnOrThrow = false;
    for (AbstractInsnNode ain : m.instructions) {
      int opcode = ain.getOpcode();
      if (opcode == RETURN || opcode == ARETURN || opcode == DRETURN ||
        opcode == FRETURN || opcode == IRETURN || opcode == LRETURN ||
        opcode == ATHROW) {
        hasReturnOrThrow = true;
        break;
      }
    }
    return !hasReturnOrThrow;
  }

  /**
   * Determines if an instruction node represents a method invocation or jump.
   *
   * @param ain The instruction node to check.
   * @return true if the instruction is a method invocation or jump, false otherwise.
   */
  public boolean isInvocationOrJump(AbstractInsnNode ain) {
    switch (ain.getType()) {
      case AbstractInsnNode.METHOD_INSN:
      case AbstractInsnNode.FIELD_INSN:
      case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
      case AbstractInsnNode.TYPE_INSN:
      case AbstractInsnNode.JUMP_INSN:
        return true;
      default:
        return false;
    }
  }
}
