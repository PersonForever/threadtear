package me.nov.threadtear.execution.cleanup.remove;

import me.nov.threadtear.execution.Clazz;
import me.nov.threadtear.execution.Execution;
import me.nov.threadtear.execution.ExecutionCategory;
import me.nov.threadtear.execution.ExecutionTag;
import me.nov.threadtear.util.ByteCodeUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.*;

/**
 * Execution to remove unused classes from the bytecode.
 * A class is considered unused if no other class imports it and it's not a root class (e.g., has a main method).
 */
public class RemovedUnusedClasses extends Execution {

  public RemovedUnusedClasses() {
    super(ExecutionCategory.CLEANING, "Remove Unused Classes","removes junk classes",
      ExecutionTag.RUNNABLE, ExecutionTag.BETTER_DECOMPILE, ExecutionTag.BETTER_DEOBFUSCATE);
  }

  @Override
  public boolean execute(Map<String, Clazz> classes, boolean verbose) {
    // Step 1: Identify Root Classes (Classes with main methods)
    Set<String> rootClasses = identifyRootClasses(classes, verbose);

    // Step 2: Identify Unused Classes
    List<String> unusedClasses = identifyUnusedClasses(classes, rootClasses, verbose);

    // Step 3: Remove Unused Classes
    removeUnusedClasses(classes, unusedClasses, verbose);

    // Step 4: Log Summary
    if (verbose) {
      logger.info("Removal of unused classes completed.");
    }

    return !unusedClasses.isEmpty();
  }

  /**
   * Identifies root classes (classes containing a main method).
   *
   * @param classes Map of class names to Clazz objects.
   * @param verbose Flag to enable verbose logging.
   * @return Set of class names that are root classes.
   */
  private Set<String> identifyRootClasses(Map<String, Clazz> classes, boolean verbose) {
    Set<String> rootClasses = new HashSet<>();

    for (Clazz clazz : classes.values()) {
      ClassNode classNode = clazz.node;
      for (MethodNode method : classNode.methods) {
        if (isMainMethod(method)) {
          rootClasses.add(classNode.name);
          if (verbose) {
            logger.debug("Identified root class (main method): {}", classNode.name.replace('/', '.'));
          }
          break; // No need to check other methods
        }
      }
    }

    if (verbose) {
      logger.debug("Total root classes identified: {}", rootClasses.size());
    }

    return rootClasses;
  }

  /**
   * Checks if a method is a main method.
   *
   * @param method The MethodNode to check.
   * @return True if the method is a main method, false otherwise.
   */
  private boolean isMainMethod(MethodNode method) {
    return method.name.equals("main") &&
      method.desc.equals("([Ljava/lang/String;)V") &&
      (method.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC)) == (Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
  }

  /**
   * Identifies unused classes that are not root classes and are not imported by any other class.
   *
   * @param classes     Map of class names to Clazz objects.
   * @param rootClasses Set of root class names.
   * @param verbose     Flag to enable verbose logging.
   * @return List of class names that are unused.
   */
  private List<String> identifyUnusedClasses(Map<String, Clazz> classes, Set<String> rootClasses, boolean verbose) {
    List<String> unusedClasses = new ArrayList<>();

    for (Clazz clazz : classes.values()) {
      String className = clazz.node.name;

      // Skip root classes
      if (rootClasses.contains(className)) {
        if (verbose) {
          logger.debug("Skipping root class: {}", className.replace('/', '.'));
        }
        continue;
      }

      // Check if any other class imports this class
      Map<String, Clazz> importingClasses = ByteCodeUtil.findallimports(classes, className.replace('/', '.'));

      // Remove self-imports (if any)
      importingClasses.remove(className);

      if (importingClasses.isEmpty()) {
        unusedClasses.add(className);
        if (verbose) {
          logger.debug("Identified unused class: {}", className.replace('/', '.'));
        }
      }
    }

    if (verbose) {
      logger.info("Total unused classes identified: {}", unusedClasses.size());
    }

    return unusedClasses;
  }

  /**
   * Removes unused classes from the class map.
   *
   * @param classes       Map of class names to Clazz objects.
   * @param unusedClasses List of class names to remove.
   * @param verbose       Flag to enable verbose logging.
   */
  private void removeUnusedClasses(Map<String, Clazz> classes, List<String> unusedClasses, boolean verbose) {
    for (String className : unusedClasses) {
      classes.remove(className);
      logger.debug("Removed unused class: {}", className.replace('/', '.'));
    }
    logger.info("Removed {} unused classes.", unusedClasses.size());
  }
}
