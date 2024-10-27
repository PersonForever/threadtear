package me.nov.threadtear.execution.cleanup.simplify;

import java.util.*;

import me.nov.threadtear.analysis.stack.ConstantTracker;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;
import me.nov.threadtear.execution.*;
import me.nov.threadtear.util.asm.Access;
import me.nov.threadtear.analysis.stack.ConstantValue;
import me.nov.threadtear.analysis.stack.IConstantReferenceHandler;

/**
 * Execution to simplify bitwise operations in Java bytecode.
 * It performs constant folding and attempts to simplify common obfuscation patterns.
 */
public class SimplifyBitOperations extends Execution implements IConstantReferenceHandler {

  public SimplifyBitOperations() {
    super(
      ExecutionCategory.CLEANING,
      "Simplify Bitwise Operations",
      "Simplifies bitwise operations by performing constant folding and simplifying common obfuscation patterns."
    );
  }

  private int simplifications = 0;

  @Override
  public boolean execute(Map<String, Clazz> classes, boolean verbose) {
    simplifications = 0;

    for (Clazz clazz : classes.values()) {
      ClassNode classNode = clazz.node;
      for (MethodNode method : classNode.methods) {
        if (Access.isAbstract(method.access) || Access.isNative(method.access)) {
          continue; // Skip abstract and native methods
        }

        try {
          simplifyMethod(classNode, method, verbose);
        } catch (Exception e) {
          clazz.addFail(e);
          if (verbose) {
            logger.error("Failed to simplify method {}.{}: {}", classNode.name, method.name, e.getMessage());
          }
        }
      }
    }

    logger.info("Simplified {} bitwise operations.", simplifications);
    return true;
  }

  /**
   * Simplifies bitwise operations within a method.
   *
   * @param classNode The class containing the method.
   * @param method    The method to simplify.
   * @param verbose   Flag to enable verbose logging.
   * @throws AnalyzerException If bytecode analysis fails.
   */
  private void simplifyMethod(ClassNode classNode, MethodNode method, boolean verbose) throws AnalyzerException {
    Analyzer<ConstantValue> analyzer = new Analyzer<>(new ConstantTracker(this, Access.isStatic(method.access), method.maxLocals, method.desc, new Object[0]));
    analyzer.analyze(classNode.name, method);
    Frame<ConstantValue>[] frames = analyzer.getFrames();
    AbstractInsnNode[] insns = method.instructions.toArray();

    for (int i = 0; i < insns.length; i++) {
      AbstractInsnNode insn = insns[i];
      int opcode = insn.getOpcode();

      if (isBitwiseOperation(opcode)) {
        Frame<ConstantValue> frame = frames[i];
        if (frame == null) continue; // Dead code

        // Depending on the operation, retrieve operands
        switch (opcode) {
          case IAND:
          case IOR:
          case IXOR:
            // Binary integer operations
            simplifyBinaryIntOperation(method, insn, frame, opcode, Type.INT_TYPE, verbose);
            break;
          case LAND:
          case LOR:
          case LXOR:
            // Binary long operations
            simplifyBinaryIntOperation(method, insn, frame, opcode, Type.LONG_TYPE, verbose);
            break;
          case ISHL:
          case ISHR:
          case IUSHR:
            // Shift operations
            simplifyShiftOperation(method, insn, frame, opcode, Type.INT_TYPE, verbose);
            break;
          case LSHL:
          case LSHR:
          case LUSHR:
            // Shift operations for long
            simplifyShiftOperation(method, insn, frame, opcode, Type.LONG_TYPE, verbose);
            break;
          default:
            break;
        }

        // Attempt to simplify common bitmask patterns
        simplifyBitMaskPattern(method, insn, frame, i, verbose);
      }
    }
  }

  /**
   * Checks if the opcode corresponds to a bitwise operation.
   *
   * @param opcode The opcode to check.
   * @return True if it's a bitwise operation, else false.
   */
  private boolean isBitwiseOperation(int opcode) {
    return opcode == IAND || opcode == IOR || opcode == IXOR ||
      opcode == LAND || opcode == LOR || opcode == LXOR ||
      opcode == ISHL || opcode == ISHR || opcode == IUSHR ||
      opcode == LSHL || opcode == LSHR || opcode == LUSHR;
  }

  /**
   * Simplifies binary integer or long bitwise operations.
   *
   * @param method   The method containing the instruction.
   * @param insn     The instruction to potentially replace.
   * @param frame    The current stack frame.
   * @param opcode   The opcode of the instruction.
   * @param type     The type of the operation (INT or LONG).
   * @param verbose  Verbose logging flag.
   */
  private void simplifyBinaryIntOperation(MethodNode method, AbstractInsnNode insn, Frame<ConstantValue> frame, int opcode, Type type, boolean verbose) {
    // For binary operations, the stack should have two operands
    ConstantValue value2 = frame.getStack(frame.getStackSize() - 1);
    ConstantValue value1 = frame.getStack(frame.getStackSize() - 2);

    if (value1.isKnown() && (value1.isInteger() || value1.isLong()) &&
      value2.isKnown() && (value2.isInteger() || value2.isLong())) {
      // Perform the bitwise operation
      long operand1 = ((Number) value1.getValue()).longValue();
      long operand2 = ((Number) value2.getValue()).longValue();
      long result = 0;

      switch (opcode) {
        case IAND:
        case LAND:
          result = operand1 & operand2;
          break;
        case IOR:
        case LOR:
          result = operand1 | operand2;
          break;
        case IXOR:
        case LXOR:
          result = operand1 ^ operand2;
          break;
        default:
          return; // Not a binary bitwise operation
      }

      // Replace the bitwise operation with the constant result
      AbstractInsnNode replacement = getConstantInsn(result, type);
      method.instructions.set(insn, replacement);
      simplifications++;

      if (verbose && logger != null) { // Ensure logger is not null
        logger.debug("Simplified bitwise operation in method {}: {} {} {} -> {}", method.name, operand1, getOpcodeName(opcode), operand2, result);
      }
    }
  }

  /**
   * Simplifies shift operations.
   *
   * @param method   The method containing the instruction.
   * @param insn     The instruction to potentially replace.
   * @param frame    The current stack frame.
   * @param opcode   The opcode of the instruction.
   * @param type     The type of the operation (INT or LONG).
   * @param verbose  Verbose logging flag.
   */
  private void simplifyShiftOperation(MethodNode method, AbstractInsnNode insn, Frame<ConstantValue> frame, int opcode, Type type, boolean verbose) {
    // For shift operations, the stack should have two operands: value and shift
    ConstantValue shiftValue = frame.getStack(frame.getStackSize() - 1);
    ConstantValue value = frame.getStack(frame.getStackSize() - 2);

    if (value.isKnown() && (value.isInteger() || value.isLong()) &&
      shiftValue.isKnown() && (shiftValue.isInteger() || shiftValue.isLong())) {
      long operand = ((Number) value.getValue()).longValue();
      long shift = ((Number) shiftValue.getValue()).longValue();
      long result = 0;

      switch (opcode) {
        case ISHL:
        case LSHL:
          result = operand << shift;
          break;
        case ISHR:
        case LSHR:
          result = operand >> shift;
          break;
        case IUSHR:
        case LUSHR:
          result = operand >>> shift;
          break;
        default:
          return; // Not a shift operation
      }

      // Replace the shift operation with the constant result
      AbstractInsnNode replacement = getConstantInsn(result, type);
      method.instructions.set(insn, replacement);
      simplifications++;

      if (verbose && logger != null) { // Ensure logger is not null
        logger.debug("Simplified shift operation in method {}: {} {} {}", method.name, operand, getOpcodeName(opcode), shift, result);
      }
    }
  }

  /**
   * Attempts to simplify common bitmask patterns.
   *
   * @param method  The method containing the instruction.
   * @param insn    The current instruction.
   * @param frame   The current stack frame.
   * @param index   The index of the instruction.
   * @param verbose Verbose logging flag.
   */
  private void simplifyBitMaskPattern(MethodNode method, AbstractInsnNode insn, Frame<ConstantValue> frame, int index, boolean verbose) {
    // Example pattern: (var0 >>> shift) & mask
    // Attempt to simplify if possible
    if (!(insn instanceof InsnNode)) return;

    int opcode = insn.getOpcode();
    if (opcode != IAND && opcode != LAND) return;

    // Get the previous instruction (should be the shift operation)
    AbstractInsnNode prevInsn = insn.getPrevious();
    if (prevInsn == null) return;

    int prevOpcode = prevInsn.getOpcode();
    if (!(prevOpcode == ISHL || prevOpcode == ISHR || prevOpcode == IUSHR ||
      prevOpcode == LSHL || prevOpcode == LSHR || prevOpcode == LUSHR)) {
      return;
    }

    // Check if the shift operation has a known shift value
    Frame<ConstantValue> shiftFrame = frame;
    ConstantValue maskValue = frame.getStack(frame.getStackSize() - 1);
    ConstantValue shiftResult = frame.getStack(frame.getStackSize() - 2);

    if (maskValue.isKnown() && (maskValue.isInteger() || maskValue.isLong())) {
      long mask = ((Number) maskValue.getValue()).longValue();

      // Attempt to determine if the mask is a power of two minus one (e.g., 1, 3, 7, 15, 31, 63, ...)
      if (isPowerOfTwoMinusOne(mask)) {
        int bitCount = Long.bitCount(mask);
        // For example, mask = 63 (0x3F) -> bitCount = 6

        // This pattern is often used to extract specific bits
        // Without knowing var0's value, we cannot simplify further
        // However, we can annotate or mark this pattern for manual review

        if (verbose) {
          logger.debug("Detected bitmask pattern in method {}: mask = {}", method.name, mask);
        }

        // Optionally, you can insert comments or metadata for manual analysis
        // Since ASM does not support comments, this step is limited
      }
    }
  }

  /**
   * Checks if a number is a power of two minus one (e.g., 1, 3, 7, 15, 31, ...).
   *
   * @param number The number to check.
   * @return True if the number is a power of two minus one, else false.
   */
  private boolean isPowerOfTwoMinusOne(long number) {
    return (number & (number + 1)) == 0 && number != 0;
  }

  /**
   * Creates a constant instruction node based on the type and value.
   *
   * @param value The constant value.
   * @param type  The type of the constant (INT or LONG).
   * @return The corresponding instruction node.
   */
  private AbstractInsnNode getConstantInsn(long value, Type type) {
    if (type.equals(Type.INT_TYPE)) {
      if (value >= -1 && value <= 5) {
        switch ((int) value) {
          case -1: return new InsnNode(ICONST_M1);
          case 0: return new InsnNode(ICONST_0);
          case 1: return new InsnNode(ICONST_1);
          case 2: return new InsnNode(ICONST_2);
          case 3: return new InsnNode(ICONST_3);
          case 4: return new InsnNode(ICONST_4);
          case 5: return new InsnNode(ICONST_5);
        }
      } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
        return new IntInsnNode(BIPUSH, (int) value);
      } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
        return new IntInsnNode(SIPUSH, (int) value);
      } else {
        return new LdcInsnNode((int) value);
      }
    } else if (type.equals(Type.LONG_TYPE)) {
      if (value == 0L || value == 1L) {
        return new InsnNode(value == 0L ? LCONST_0 : LCONST_1);
      } else {
        return new LdcInsnNode(value);
      }
    }
    return new LdcInsnNode(value);
  }

  /**
   * Retrieves the opcode name for logging purposes.
   *
   * @param opcode The opcode to get the name for.
   * @return The name of the opcode.
   */
  private String getOpcodeName(int opcode) {
    switch (opcode) {
      case IAND: return "IAND";
      case IOR: return "IOR";
      case IXOR: return "IXOR";
      case LAND: return "LAND";
      case LOR: return "LOR";
      case LXOR: return "LXOR";
      case ISHL: return "ISHL";
      case ISHR: return "ISHR";
      case IUSHR: return "IUSHR";
      case LSHL: return "LSHL";
      case LSHR: return "LSHR";
      case LUSHR: return "LUSHR";
      default: return "UNKNOWN";
    }
  }

  /**
   * Implementation of IConstantReferenceHandler interface methods.
   * These methods are required for constant tracking but are not utilized in this execution.
   */

  @Override
  public Object getFieldValueOrNull(BasicValue v, String owner, String name, String desc) {
    // Not required for this execution
    return null;
  }

  @Override
  public Object getMethodReturnOrNull(BasicValue v, String owner, String name, String desc, List<? extends ConstantValue> values) {
    return null;
  }


}
