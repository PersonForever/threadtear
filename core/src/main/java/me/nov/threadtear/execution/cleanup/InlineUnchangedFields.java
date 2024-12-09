package me.nov.threadtear.execution.cleanup;

import me.nov.threadtear.execution.*;
import me.nov.threadtear.util.asm.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.lang.reflect.Field;
import java.security.SecureClassLoader;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static org.objectweb.asm.Opcodes.*;


public class InlineUnchangedFields extends Execution {

  private Map<String, Clazz> classes;
  private List<FieldInsnNode> fieldAssignments; // All field assignment instructions
  private int inlinedCount;

  // Map: className -> (fieldName+desc -> runtime value)
  private Map<String, Map<String, Object>> constantFieldValues = new HashMap<>();

  public InlineUnchangedFields() {
    super(
      ExecutionCategory.CLEANING,
      "Inline unchanged fields (Reflection Runtime) with merged <clinit>",
      "Loads classes, merges multiple <clinit>, runs <clinit>, and uses reflection to determine static field values.<br>" +
        "Then inlines these values in all references.",
      ExecutionTag.RUNNABLE,
      ExecutionTag.BETTER_DECOMPILE,
      ExecutionTag.BETTER_DEOBFUSCATE
    );
  }

  @Override
  public boolean execute(Map<String, Clazz> classes, boolean verbose) {
    this.classes = classes;
    this.inlinedCount = 0;

    // Collect all field assignment instructions
    this.fieldAssignments = classes.values().stream()
      .map(c -> c.node.methods)
      .flatMap(List::stream)
      .map(m -> m.instructions.spliterator())
      .flatMap(insns -> StreamSupport.stream(insns, false))
      .filter(ain -> ain.getOpcode() == PUTFIELD || ain.getOpcode() == PUTSTATIC)
      .map(ain -> (FieldInsnNode) ain)
      .collect(Collectors.toList());

    // Merge multiple <clinit> methods if present
    for (Clazz clazz : this.classes.values()) {
      mergeClinitMethods(clazz.node);
    }

    // Load all classes using a custom ClassLoader
    ReflectiveClassLoader loader = new ReflectiveClassLoader(getClass().getClassLoader());
    Map<String, Class<?>> loadedClasses = defineAllClasses(loader, this.classes);

    // Determine which fields can be considered constant
    for (Clazz clazz : this.classes.values()) {
      ClassNode cn = clazz.node;
      if (!Access.isEnum(cn.access)) {
        analyzeClinitForConstants(cn, loadedClasses);
      }
    }

    // Inline all references to these constant fields
    try{
      inlineAllConstantFields();
    } catch (Exception e) {
      logger.error("Error inlining constant fields: {}", e.getMessage());
      return false;
    }


    logger.info("Inlined {} field references!", inlinedCount);
    return inlinedCount > 0;
  }

  /**
   * Merge multiple <clinit> methods into a single one if found.
   * Java normally allows only one <clinit>, but in manipulated bytecode,
   * there might be multiple. We combine them for easier analysis.
   */
  private void mergeClinitMethods(ClassNode cn) {
    List<MethodNode> clinitMethods = new ArrayList<>();
    for (MethodNode m : cn.methods) {
      if (m.name.equals("<clinit>") && m.desc.equals("()V")) {
        clinitMethods.add(m);
      }
    }

    // If there's only one or none, nothing to do
    if (clinitMethods.size() <= 1) {
      return;
    }

    // We have multiple <clinit> methods. Let's merge them into the first one.
    MethodNode primary = clinitMethods.get(0);

    for (int i = 1; i < clinitMethods.size(); i++) {
      MethodNode extra = clinitMethods.get(i);

      // We'll merge instructions from 'extra' into 'primary'
      // Just before primary's RETURN instruction (or at the end if no explicit return)
      AbstractInsnNode insertionPoint = findMethodReturnOrEnd(primary);

      // Clone labels
      Map<LabelNode, LabelNode> labelMap = Instructions.cloneLabels(extra.instructions);

      // Copy instructions
      InsnList extraCopy = new InsnList();
      for (AbstractInsnNode ain : extra.instructions) {
        if (ain.getType() == AbstractInsnNode.LABEL ||
          ain.getType() == AbstractInsnNode.FRAME ||
          ain.getType() == AbstractInsnNode.LINE ||
          ain.getOpcode() != RETURN) {
          extraCopy.add(ain.clone(labelMap));
        }
      }

      // Insert the copied instructions before the return
      primary.instructions.insertBefore(insertionPoint, extraCopy);

      // Merge try-catch blocks
      if (extra.tryCatchBlocks != null) {
        for (TryCatchBlockNode tcb : extra.tryCatchBlocks) {
          TryCatchBlockNode copyTcb = new TryCatchBlockNode(
            labelMap.get(tcb.start),
            labelMap.get(tcb.end),
            labelMap.get(tcb.handler),
            tcb.type
          );
          primary.tryCatchBlocks.add(copyTcb);
        }
      }

      // Merge local variables
      if (extra.localVariables != null) {
        if (primary.localVariables == null) {
          primary.localVariables = new ArrayList<>();
        }
        for (LocalVariableNode lv : extra.localVariables) {
          LocalVariableNode copyLv = new LocalVariableNode(
            lv.name,
            lv.desc,
            lv.signature,
            labelMap.get(lv.start),
            labelMap.get(lv.end),
            lv.index
          );
          primary.localVariables.add(copyLv);
        }
      }
    }

    // Remove all extra <clinit> methods
    cn.methods.removeIf(m -> m.name.equals("<clinit>") && m != primary);
  }

  /**
   * Find a suitable point in the primary method to insert extra <clinit> instructions.
   * We prefer to insert before the RETURN instruction if found, else insert at the end.
   */
  private AbstractInsnNode findMethodReturnOrEnd(MethodNode m) {
    for (AbstractInsnNode ain = m.instructions.getLast(); ain != null; ain = ain.getPrevious()) {
      int op = ain.getOpcode();
      if (op >= IRETURN && op <= RETURN) {
        return ain; // found a return instruction
      }
    }
    // No return found, insert at the very end
    return m.instructions.getLast();
  }

  private Map<String, Class<?>> defineAllClasses(ReflectiveClassLoader loader, Map<String, Clazz> classes) {
    Map<String, Class<?>> result = new HashMap<>();
    for (Map.Entry<String, Clazz> e : classes.entrySet()) {
      String className = e.getKey();
      ClassNode cn = e.getValue().node;
      byte[] classBytes = Instructions.toByteArray(cn);
      Class<?> definedClass = loader.define(className.replace('/', '.'), classBytes);
      result.put(className, definedClass);
    }
    return result;
  }

  private void analyzeClinitForConstants(ClassNode cn, Map<String, Class<?>> loadedClasses) {
    MethodNode clinit = null;
    for (MethodNode m : cn.methods) {
      if (m.name.equals("<clinit>") && m.desc.equals("()V")) {
        clinit = m;
        break;
      }
    }

    if (clinit == null) return;

    Class<?> runtimeClass = loadedClasses.get(cn.name);
    if (runtimeClass == null) {
      return; // Could not load class, skip
    }

    // Check each static field to see if it's never assigned outside <clinit>
    for (FieldNode fn : cn.fields) {
      if ((fn.access & ACC_STATIC) == 0) {
        continue; // only handle static fields
      }

      boolean assignedOutsideClinit = fieldAssignments.stream()
        .anyMatch(fin -> isFieldReferenceTo(cn, fn, fin) && !isInClinit(cn, fin));
      if (!assignedOutsideClinit) {
        try {
          Field f = runtimeClass.getDeclaredField(fn.name);
          f.setAccessible(true);
          Object value = f.get(null);

          // Store discovered value
          constantFieldValues
            .computeIfAbsent(cn.name, k -> new HashMap<>())
            .put(fn.name + fn.desc, value);
        } catch (NoSuchFieldException | IllegalAccessException ex) {
          // Can't access field, skip
        }
      }
    }
  }

  private void inlineAllConstantFields() {
    for (Clazz c : classes.values()) {
      ClassNode cn = c.node;
      Map<String, Object> fieldMap = constantFieldValues.getOrDefault(cn.name, Collections.emptyMap());

      if (!fieldMap.isEmpty()) {
        for (MethodNode m : cn.methods) {
          List<AbstractInsnNode> toReplace = new ArrayList<>();
          for (AbstractInsnNode ain : m.instructions) {
            if (ain.getType() == AbstractInsnNode.FIELD_INSN) {
              FieldInsnNode fin = (FieldInsnNode) ain;
              String key = fin.name + fin.desc;
              if (fieldMap.containsKey(key) && (fin.getOpcode() == GETSTATIC)) {
                toReplace.add(ain);
              }
            }
          }

          for (AbstractInsnNode insn : toReplace) {
            FieldInsnNode fin = (FieldInsnNode) insn;
            Object constantValue = fieldMap.get(fin.name + fin.desc);
            Type fieldType = Type.getType(fin.desc);

            AbstractInsnNode replacement = Instructions.makeConstantPush(constantValue, fieldType);
            m.instructions.set(insn, replacement);
            inlinedCount++;
            logger.debug("Inlined field {}.{} in method {} of class {} with value {}",
              fin.owner, fin.name, m.name, cn.name, constantValue);
          }
        }
      }
    }
  }

  private boolean isFieldReferenceTo(ClassNode cn, FieldNode fn, FieldInsnNode fin) {
    return fin.owner.equals(cn.name) && fin.name.equals(fn.name) && fin.desc.equals(fn.desc);
  }

  private boolean isInClinit(ClassNode cn, FieldInsnNode fin) {
    for (MethodNode m : cn.methods) {
      if (m.name.equals("<clinit>") && m.desc.equals("()V")) {
        for (AbstractInsnNode ain : m.instructions) {
          if (ain == fin) {
            return true;
          }
        }
      }
    }
    return false;
  }

  public static class ReflectiveClassLoader extends SecureClassLoader {
    public ReflectiveClassLoader(ClassLoader parent) {
      super(parent);
    }

    public Class<?> define(String name, byte[] b) {
      Class<?> c = defineClass(name, b, 0, b.length);
      resolveClass(c);
      return c;
    }
  }
}
