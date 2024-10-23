package me.nov.threadtear.execution;


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
