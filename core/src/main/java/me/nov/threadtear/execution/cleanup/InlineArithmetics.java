package me.nov.threadtear.execution.cleanup;

import me.nov.threadtear.execution.Clazz;
import me.nov.threadtear.execution.Execution;
import me.nov.threadtear.execution.ExecutionCategory;
import me.nov.threadtear.execution.ExecutionTag;

import java.util.Map;

public class InlineArithmetics extends Execution {

  public InlineArithmetics() {
    super(ExecutionCategory.CLEANING, "Inline arithmetics",
        "Inline arithmetic calculations.<br>Can be useful for deobfuscating arithmetic obfuscation used in flow.",
        ExecutionTag.SHRINK, ExecutionTag.RUNNABLE);
  }

  @Override
  public boolean execute(Map<String, Clazz> classes, boolean verbose) {


    return false;
  }
}
