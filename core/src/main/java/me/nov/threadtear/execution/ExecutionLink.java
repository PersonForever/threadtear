package me.nov.threadtear.execution;

import me.nov.threadtear.execution.allatori.ExpirationDateRemoverAllatori;
import me.nov.threadtear.execution.allatori.JunkRemoverAllatori;
import me.nov.threadtear.execution.allatori.StringObfuscationAllatori;
import me.nov.threadtear.execution.analysis.*;
import me.nov.threadtear.execution.cleanup.InlineMethods;
import me.nov.threadtear.execution.cleanup.InlineUnchangedFields;
import me.nov.threadtear.execution.cleanup.remove.RemoveAttributes;
import me.nov.threadtear.execution.cleanup.remove.RemoveUnnecessary;
import me.nov.threadtear.execution.cleanup.remove.RemoveUnusedVariables;
import me.nov.threadtear.execution.dasho.StringObfuscationDashO;
import me.nov.threadtear.execution.generic.ConvertCompareInstructions;
import me.nov.threadtear.execution.generic.KnownConditionalJumps;
import me.nov.threadtear.execution.generic.ObfuscatedAccess;
import me.nov.threadtear.execution.generic.TryCatchObfuscationRemover;
import me.nov.threadtear.execution.generic.inliner.ArgumentInliner;
import me.nov.threadtear.execution.generic.inliner.JSRInliner;
import me.nov.threadtear.execution.paramorphism.AccessObfuscationParamorphism;
import me.nov.threadtear.execution.paramorphism.BadAttributeRemover;
import me.nov.threadtear.execution.paramorphism.StringObfuscationParamorphism;
import me.nov.threadtear.execution.stringer.AccessObfuscationStringer;
import me.nov.threadtear.execution.stringer.StringObfuscationStringer;
import me.nov.threadtear.execution.tools.*;
import me.nov.threadtear.execution.zkm.*;
import me.nov.threadtear.logging.LogWrapper;
import me.nov.threadtear.util.reflection.ReflectionUtil;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

public class ExecutionLink {
  public static final List<Class<? extends Execution>> executions = new ArrayList<Class<? extends Execution>>() {};
  static {
    // Use reflection to get every class in the execution package and add it if it extends Execution
    Class<?>[] classes = ReflectionUtil.getClassInPackage("me.nov.threadtear.execution");
    LogWrapper.logger.info("Found " + classes.length + " classes in execution package");
    for(Class<?> clazz : classes){
      // Skip the Execution class itself, abstract classes, and interfaces
      if(Execution.class.isAssignableFrom(clazz) && clazz != Execution.class && !Modifier.isAbstract(clazz.getModifiers()) && !clazz.isInterface()){
        try {
          // Check if the class has a public no-argument constructor
          clazz.getConstructor();
          // Add the class directly to the list without instantiating
          executions.add((Class<? extends Execution>) clazz);
        } catch (NoSuchMethodException e) {
          // The class doesn't have a public no-argument constructor; skip it
          continue;
        }
      }
    }

  }
}
