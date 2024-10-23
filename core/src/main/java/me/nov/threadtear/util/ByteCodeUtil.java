package me.nov.threadtear.util;


import me.nov.threadtear.execution.Clazz;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ByteCodeUtil {
  /**
   * Finds all classes that import the specified class.
   *
   * @param classes        The map of class names to Clazz objects.
   * @param specificClass  The name of the specific class to find imports for.
   * @return A map of class names to Clazz objects that import the specific class.
   */
  public static Map<String, Clazz> findallimports(Map<String, Clazz> classes, String specificClass) {
    Map<String, Clazz> result = new HashMap<>();

    for (Map.Entry<String, Clazz> entry : classes.entrySet()) {
      Clazz clazz = entry.getValue();
      if (importsClass(clazz, specificClass)) {
        result.put(entry.getKey(), clazz);
      }
    }

    return result;
  }

  /**
   * Checks if the given class imports the specified class.
   *
   * @param clazz          The Clazz object to check.
   * @param specificClass  The name of the specific class to check for.
   * @return True if the clazz imports the specific class, false otherwise.
   */
  private static boolean importsClass(Clazz clazz, String specificClass) {
    ClassNode classNode = clazz.node;
    for (MethodNode method : classNode.methods) {
      for (AbstractInsnNode instruction : method.instructions) {
        if (instruction instanceof MethodInsnNode) {
          MethodInsnNode methodInsn = (MethodInsnNode) instruction;
          if (methodInsn.owner.equals(specificClass.replace('.', '/'))) {
            return true;
          }
        }
      }
    }
    return false;
  }

  public static List<String> findVariableModifications(Map<String, Clazz> classes, Clazz Class, int varIndex) {
    List<String> modifications = new ArrayList<>();
    String targetClassName = Class.node.name;

    // Retrieve the list of fields from the target class
    List<FieldNode> fields = Class.node.fields;
    if (varIndex < 0 || varIndex >= fields.size()) {
      // Invalid varIndex
      return modifications;
    }
    FieldNode targetField = fields.get(varIndex);
    String targetFieldName = targetField.name;
    String targetFieldDesc = targetField.desc;

    for (Clazz clazz : classes.values()) {
      ClassNode classNode = clazz.node;
      for (MethodNode method : classNode.methods) {
        InsnList instructions = method.instructions;
        for (AbstractInsnNode instruction : instructions) {
          if (instruction instanceof FieldInsnNode) {
            FieldInsnNode fieldInsn = (FieldInsnNode) instruction;
            if ((fieldInsn.getOpcode() == Opcodes.PUTFIELD || fieldInsn.getOpcode() == Opcodes.PUTSTATIC)
              && fieldInsn.owner.equals(targetClassName)
              && fieldInsn.name.equals(targetFieldName)
              && fieldInsn.desc.equals(targetFieldDesc)) {
              // Record the modification
              String modificationDetail = "Field " + fieldInsn.owner.replace('/', '.') + "." + fieldInsn.name
                + " modified in method " + method.name + " of class " + classNode.name.replace('/', '.');
              modifications.add(modificationDetail);
            }
          }
        }
      }
    }
    return modifications;
  }


  /**
   * Checks if the given opcode corresponds to a variable modification.
   *
   * @param opcode The opcode to check.
   * @return True if the opcode is a modification, false otherwise.
   */
  private static boolean isModificationOpcode(int opcode) {
    // Opcodes for variable modification (store instructions)
    return opcode == Opcodes.ISTORE || opcode == Opcodes.LSTORE || opcode == Opcodes.FSTORE ||
      opcode == Opcodes.DSTORE || opcode == Opcodes.ASTORE;
  }
}
