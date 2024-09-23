package me.nov.threadtear.util.reflection;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ReflectionUtil {
  public static Class<?>[] getClassInPackage(String packageName) {
    List<Class<?>> classes = new ArrayList<>();
    String path = packageName.replace('.', '/');
    try {
      Enumeration<URL> resources = Thread.currentThread().getContextClassLoader().getResources(path);
      while (resources.hasMoreElements()) {
        URL resource = resources.nextElement();
        if (resource.getProtocol().equals("file")) {
          classes.addAll(findClasses(new File(resource.getFile()), packageName));
        } else if (resource.getProtocol().equals("jar")) {
          String jarPath = resource.getPath().substring(5, resource.getPath().indexOf("!"));
          classes.addAll(findClassesInJar(jarPath, path));
        }
      }
    } catch (IOException | ClassNotFoundException e) {
      e.printStackTrace();
    }
    return classes.toArray(new Class<?>[0]);
  }

  private static List<Class<?>> findClasses(File directory, String packageName) throws ClassNotFoundException {
    List<Class<?>> classes = new ArrayList<>();
    if (!directory.exists()) {
      return classes;
    }
    File[] files = directory.listFiles();
    if (files != null) {
      for (File file : files) {
        if (file.isDirectory()) {
          classes.addAll(findClasses(file, packageName + "." + file.getName()));
        } else if (file.getName().endsWith(".class")) {
          classes.add(Class.forName(packageName + '.' + file.getName().substring(0, file.getName().length() - 6)));
        }
      }
    }
    return classes;
  }

  private static List<Class<?>> findClassesInJar(String jarPath, String packagePath) throws IOException, ClassNotFoundException {
    List<Class<?>> classes = new ArrayList<>();
    JarFile jarFile = new JarFile(jarPath);
    Enumeration<JarEntry> entries = jarFile.entries();
    while (entries.hasMoreElements()) {
      JarEntry entry = entries.nextElement();
      String entryName = entry.getName();
      if (entryName.startsWith(packagePath) && entryName.endsWith(".class") && !entry.isDirectory()) {
        String className = entryName.replace('/', '.').substring(0, entryName.length() - 6);
        classes.add(Class.forName(className));
      }
    }
    jarFile.close();
    return classes;
  }
}
