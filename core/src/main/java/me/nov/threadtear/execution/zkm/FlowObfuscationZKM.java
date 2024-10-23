package me.nov.threadtear.execution.zkm;

import me.nov.threadtear.execution.Clazz;
import me.nov.threadtear.execution.Execution;
import me.nov.threadtear.execution.ExecutionCategory;
import me.nov.threadtear.execution.ExecutionTag;
import me.nov.threadtear.util.asm.Access;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

public class FlowObfuscationZKM extends Execution {

  private static final Predicate<Integer> singleJump =
    op -> (op >= IFEQ && op <= IFLE) || op == IFNULL || op == IFNONNULL;

  public FlowObfuscationZKM() {
    super(ExecutionCategory.ZKM, "Flow obfuscation removal",
          "Rewritten and needs to be teseted", ExecutionTag.POSSIBLE_DAMAGE,
          ExecutionTag.BETTER_DECOMPILE);
  }

  @Override
  public boolean execute(Map<String, Clazz> classes, boolean verbose) {
    AtomicInteger counter = new AtomicInteger();

    classes.values().forEach(clazz -> {
      ClassNode classNode = clazz.node;

      classNode.methods.stream()
        .filter(methodNode -> !Access.isAbstract(methodNode.access) && !Access.isNative(methodNode.access))
        .forEach(methodNode -> {
          int originalTryCatchCount = methodNode.tryCatchBlocks.size();

          methodNode.tryCatchBlocks.removeIf(tc -> {
            AbstractInsnNode handlerNext = tc.handler.getNext();
            if (handlerNext == null) return false;

            int opcode = handlerNext.getOpcode();

            // Check for INVOKESTATIC followed by ATHROW
            if (opcode == Opcodes.INVOKESTATIC) {
              AbstractInsnNode nextNext = handlerNext.getNext();
              return nextNext != null && nextNext.getOpcode() == Opcodes.ATHROW;
            }
            // Check for ATHROW directly
            else if (opcode == Opcodes.ATHROW) {
              return true;
            }
            return false;
          });

          int removedTryCatchCount = originalTryCatchCount - methodNode.tryCatchBlocks.size();
          counter.addAndGet(removedTryCatchCount);
        });
    });

    logger.info("[ZKM] Removed {} fake try-catch blocks.", counter.get());
    return counter.get() > 0;
  }
}
