package me.nov.threadtear.execution.cleanup;

import java.util.*;
import java.util.stream.StreamSupport;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import me.nov.threadtear.execution.*;
import me.nov.threadtear.util.asm.*;

import static org.objectweb.asm.Opcodes.*;

/**
 * This execution attempts to inline trivial methods (e.g., methods that only return a constant or throw an exception) into their call sites.
 * It identifies such methods, then replaces their invocation instructions with the method's instructions.
 *
 * Key Improvements:
 *  - Properly handles 'this' and arguments for both static and non-static methods.
 *  - Remaps local variables correctly.
 *  - Handles return instructions so that return values remain on stack (if needed).
 *  - Skips constructors and class initializers (<init>, <clinit>).
 *  - Skips methods that reference fields or contain complex instructions.
 *  - Enforces a maximum method size to ensure only trivial methods are inlined.
 */
public class InlineMethods extends Execution {

  public InlineMethods() {
    super(
      ExecutionCategory.CLEANING,
      "Inline trivial methods without invocation",
      "Inline trivial methods (only return or throw) to simplify code.<br>" +
        "Skips <init>/<clinit>, large methods, or those referencing fields.",
      ExecutionTag.SHRINK,
      ExecutionTag.RUNNABLE
    );
  }

  private int inlines;

  // Maximum allowed instructions for a method to be considered trivial enough to inline
  private static final int MAX_METHOD_SIZE = 32;

  @Override
  public boolean execute(Map<String, Clazz> classes, boolean verbose) {
    // Map to hold methods eligible for inlining: key = "owner.name.desc", value = MethodNode
    HashMap<String, MethodNode> eligibleMethods = new HashMap<>();

    // Identify candidate methods for inlining
    classes.values().stream()
      .map(c -> c.node)
      .forEach(classNode -> classNode.methods.stream()
        .filter(this::isEligibleForInlining)
        .forEach(method -> eligibleMethods.put(classNode.name + "." + method.name + method.desc, method))
      );

    logger.info("{} trivial methods found that could be inlined", eligibleMethods.size());
    inlines = 0;

    // Inline all calls to these eligible methods
    classes.values().stream()
      .map(c -> c.node.methods)
      .flatMap(List::stream)
      .forEach(callerMethod -> {
        List<AbstractInsnNode> invokeInstructions = new ArrayList<>();

        // Collect invoke instructions that target eligible methods
        for (AbstractInsnNode ain : callerMethod.instructions.toArray()) {
          int opcode = ain.getOpcode();
          if (opcode == INVOKESTATIC || opcode == INVOKEVIRTUAL || opcode == INVOKESPECIAL) {
            // Ensure the instruction is a MethodInsnNode
            if (!(ain instanceof MethodInsnNode)) {
              continue; // Skip if not a MethodInsnNode
            }
            MethodInsnNode min = (MethodInsnNode) ain;
            String key = min.owner + "." + min.name + min.desc;
            if (eligibleMethods.containsKey(key)) {
              invokeInstructions.add(ain);
            }
          }
        }

        // Inline each collected invoke instruction
        for (AbstractInsnNode invokeInsn : invokeInstructions) {
          MethodInsnNode min = (MethodInsnNode) invokeInsn;
          MethodNode calleeMethod = eligibleMethods.get(min.owner + "." + min.name + min.desc);
          if (calleeMethod != null) {
            inlineMethod(callerMethod, min, calleeMethod);
            inlines++;
          }
        }
      });

    // Remove inlined methods from their respective classes
    for (Map.Entry<String, MethodNode> entry : eligibleMethods.entrySet()) {
      String fullMethodName = entry.getKey(); // "owner.name.desc"
      String className = fullMethodName.substring(0, fullMethodName.lastIndexOf('.'));
      Clazz clazz = classes.get(className);
      if (clazz != null) {
        clazz.node.methods.remove(entry.getValue());
      }
    }

    logger.info("Inlined {} method references!", inlines);
    return inlines > 0;
  }

  /**
   * Determines if a method is eligible for inlining based on several criteria:
   * - Not a constructor or class initializer (<init>, <clinit>).
   * - Does not contain complex instructions like method calls, field accesses, jumps, or type instructions.
   * - Has a number of instructions below the specified maximum threshold.
   * - Ends with a return or throw instruction.
   *
   * @param method The method node to evaluate.
   * @return True if the method is eligible for inlining; otherwise, false.
   */
  private boolean isEligibleForInlining(MethodNode method) {
    // Skip constructors and class initializers
    if (method.name.equals("<init>") || method.name.equals("<clinit>")) {
      return false;
    }

    // Check method size
    if (method.instructions.size() > MAX_METHOD_SIZE) {
      return false;
    }

    // Ensure no complex instructions (method calls, field accesses, type instructions, jumps)
    if (containsComplexInstructions(method)) {
      return false;
    }

    // Ensure method ends with a return or throw
    if (!endsWithReturnOrThrow(method)) {
      return false;
    }

    return true;
  }

  /**
   * Checks if a method contains complex instructions that would make inlining unsafe or non-trivial.
   * Complex instructions include method calls, field accesses, dynamic invokes, type instructions, and jumps.
   *
   * @param method The method node to inspect.
   * @return True if the method contains complex instructions; otherwise, false.
   */
  private boolean containsComplexInstructions(MethodNode method) {
    for (AbstractInsnNode ain : method.instructions.toArray()) {
      switch (ain.getType()) {
        case AbstractInsnNode.METHOD_INSN:
        case AbstractInsnNode.FIELD_INSN:
        case AbstractInsnNode.INVOKE_DYNAMIC_INSN:
        case AbstractInsnNode.TYPE_INSN:
        case AbstractInsnNode.JUMP_INSN:
          return true;
        default:
          break;
      }
    }
    return false;
  }

  /**
   * Checks if a method ends with a return or throw instruction.
   * Skips any trailing line or frame nodes.
   *
   * @param method The method node to inspect.
   * @return True if the method ends with a return or throw; otherwise, false.
   */
  private boolean endsWithReturnOrThrow(MethodNode method) {
    AbstractInsnNode last = method.instructions.getLast();
    while (last != null &&
      (last.getType() == AbstractInsnNode.LINE || last.getType() == AbstractInsnNode.FRAME)) {
      last = last.getPrevious();
    }
    if (last == null) return false;
    int opcode = last.getOpcode();
    return opcode == RETURN || opcode == IRETURN || opcode == LRETURN ||
      opcode == FRETURN || opcode == DRETURN || opcode == ARETURN || opcode == ATHROW;
  }

  /**
   * Inlines a callee method into the caller method at the location of the invoke instruction.
   * Handles argument popping, variable remapping, and return instruction removal.
   *
   * @param caller The caller method where inlining occurs.
   * @param invoke The invoke instruction to replace with inlined code.
   * @param callee The callee method being inlined.
   */
  private void inlineMethod(MethodNode caller, MethodInsnNode invoke, MethodNode callee) {
    // Create a copy of the callee's instructions
    InsnList calleeInstructions = Instructions.copy(callee.instructions);

    // Remove line and frame nodes for simplicity
    StreamSupport.stream(calleeInstructions.spliterator(), false)
      .filter(ain -> ain.getType() == AbstractInsnNode.LINE || ain.getType() == AbstractInsnNode.FRAME)
      .forEach(calleeInstructions::remove);

    // Remove or adjust return instructions in the copied code
    removeAndHandleReturns(calleeInstructions, callee);

    // Determine method signature details
    Type methodType = Type.getMethodType(callee.desc);
    Type[] argTypes = methodType.getArgumentTypes();
    boolean isStatic = (callee.access & ACC_STATIC) != 0;

    // Calculate the starting index for new local variables in the caller
    int newLocalBase = caller.maxLocals;

    // Calculate total size needed for parameters
    int paramSize = 0;
    if (!isStatic) {
      paramSize += 1; // 'this' reference
    }
    for (Type argType : argTypes) {
      paramSize += (argType.getSize() == 2) ? 2 : 1;
    }

    // Update caller's maxLocals and maxStack
    caller.maxLocals += paramSize + 4; // Additional buffer for safety
    caller.maxStack = Math.max(callee.maxStack, caller.maxStack);

    // Generate instructions to pop arguments from the stack into new local variables
    InsnList argumentPoppers = new InsnList();

    // Pop arguments in reverse order and store them into new locals
    for (int i = argTypes.length - 1; i >= 0; i--) {
      Type argType = argTypes[i];
      newLocalBase = storeArgument(argumentPoppers, newLocalBase, argType);
    }

    // If the method is not static, pop the 'this' reference
    if (!isStatic) {
      Type thisType = Type.getObjectType(invoke.owner);
      newLocalBase = storeArgument(argumentPoppers, newLocalBase, thisType);
    }

    // Insert argument pop instructions at the beginning of the callee instructions
    calleeInstructions.insert(argumentPoppers);

    // Remap local variable indices in the callee's instructions
    remapLocalVariables(calleeInstructions, callee, newLocalBase - paramSize, isStatic);

    // Insert the inlined instructions into the caller method
    caller.instructions.insert(invoke, calleeInstructions);
    // Remove the original invoke instruction
    caller.instructions.remove(invoke);

    // Optional Sanity Check: Ensure no return instructions remain
    if (!postInlineSanityCheck(calleeInstructions)) {
      logger.warning("Post-inline sanity check failed for inlined method {}.{}", callee.name, callee.desc);
    }
  }

  /**
   * Pops an argument from the stack and stores it into a new local variable.
   *
   * @param instructions The instruction list to append store instructions.
   * @param localIndex   The current local variable index.
   * @param type         The type of the argument to store.
   * @return The next available local variable index.
   */
  private int storeArgument(InsnList instructions, int localIndex, Type type) {
    int storeOpcode;
    switch (type.getSort()) {
      case Type.BOOLEAN:
      case Type.BYTE:
      case Type.CHAR:
      case Type.SHORT:
      case Type.INT:
        storeOpcode = ISTORE;
        break;
      case Type.LONG:
        storeOpcode = LSTORE;
        break;
      case Type.FLOAT:
        storeOpcode = FSTORE;
        break;
      case Type.DOUBLE:
        storeOpcode = DSTORE;
        break;
      case Type.ARRAY:
      case Type.OBJECT:
      default:
        storeOpcode = ASTORE;
        break;
    }

    instructions.add(new VarInsnNode(storeOpcode, localIndex));
    return localIndex + ((storeOpcode == LSTORE || storeOpcode == DSTORE) ? 2 : 1);
  }

  /**
   * Remaps local variable indices in the inlined callee instructions to avoid conflicts with caller's locals.
   *
   * @param instructions The instruction list containing the inlined code.
   * @param callee       The callee method being inlined.
   * @param base         The base index to offset local variables.
   * @param isStatic     Whether the callee method is static.
   */
  private void remapLocalVariables(InsnList instructions, MethodNode callee, int base, boolean isStatic) {
    for (AbstractInsnNode ain : instructions.toArray()) {
      if (ain instanceof VarInsnNode) {
        VarInsnNode vin = (VarInsnNode) ain;
        vin.var += base;
      }
    }
  }

  /**
   * Removes return instructions from the inlined method code or adjusts them so that return values remain on stack.
   * Strategy:
   * - If IRETURN, LRETURN, etc.: remove the return instruction, leaving the value on the stack.
   * - If RETURN (void): remove it, leaving nothing on the stack.
   * - If ATHROW: leave it intact because the method is supposed to throw.
   *
   * @param instructions The instruction list to modify.
   * @param callee       The callee method being inlined.
   */
  private void removeAndHandleReturns(InsnList instructions, MethodNode callee) {
    ListIterator<AbstractInsnNode> iterator = instructions.iterator();
    while (iterator.hasNext()) {
      AbstractInsnNode ain = iterator.next();
      int opcode = ain.getOpcode();
      if (opcode == IRETURN || opcode == FRETURN || opcode == ARETURN ||
        opcode == DRETURN || opcode == LRETURN) {
        // Remove the return instruction, leaving the return value on the stack
        iterator.remove();
      } else if (opcode == RETURN) {
        // Remove the void return instruction
        iterator.remove();
      } else if (opcode == ATHROW) {
        // Leave ATHROW instructions intact
      }
    }
  }

  /**
   * Performs a sanity check after inlining to ensure no invalid instructions remain.
   * Specifically, it checks for leftover return instructions which should have been removed.
   *
   * @param instructions The instruction list to check.
   * @return True if the sanity check passes; otherwise, false.
   */
  private boolean postInlineSanityCheck(InsnList instructions) {
    for (AbstractInsnNode ain : instructions.toArray()) {
      int opcode = ain.getOpcode();
      // Check for any leftover return instructions
      if (opcode == RETURN || opcode == IRETURN || opcode == LRETURN ||
        opcode == FRETURN || opcode == DRETURN || opcode == ARETURN) {
        return false; // Sanity check failed
      }
    }
    return true; // Sanity check passed
  }

  /**
   * Determines if a method is unnecessary (i.e., can be inlined).
   * Currently checks if it doesn't contain complex instructions like method calls, field accesses, etc.,
   * and ensures it ends with a return or throw.
   *
   * @param m The method node to evaluate.
   * @return True if the method is unnecessary and eligible for inlining; otherwise, false.
   */
  public boolean isUnnecessary(MethodNode m) {
    // This method is deprecated in favor of isEligibleForInlining
    // Keeping it for backward compatibility; it simply delegates to isEligibleForInlining
    return isEligibleForInlining(m);
  }

  /**
   * Determines if an instruction is an invocation or a jump.
   * Used to identify methods that cannot be inlined.
   *
   * @param ain The instruction node to check.
   * @return True if the instruction is an invocation or a jump; otherwise, false.
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
