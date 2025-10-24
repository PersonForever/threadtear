package me.nov.threadtear;

import me.nov.threadtear.vm.VM;
import org.objectweb.asm.tree.ClassNode;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.List;
import java.util.Objects;

public class CoreUtils 
{
    public static String getVersion() 
    {
        try 
        {
            return Objects.requireNonNull(CoreUtils.class.getPackage().getImplementationVersion());
        } 
        catch (NullPointerException e) 
        {
            return "(dev)";
        }
    }

    public static boolean isNoverify() 
    {
        RuntimeMXBean rtMxBean = ManagementFactory.getRuntimeMXBean();
        List<String> lstArguments = rtMxBean.getInputArguments();
        return lstArguments.contains("-Xverify:none");
    }

    public static boolean isAttachable() 
    {
        try 
        {
            Class.forName("com.sun.tools.attach.VirtualMachine");
            return true;
        } 
        catch (Exception e) 
        {
            return false;
        }
    }

    public static int getCurrentJavaVersion() 
    {
        String strVersion = System.getProperty("java.version");
        if (strVersion.startsWith("1.")) 
        {
            return Integer.parseInt(strVersion.substring(2, 3));
        } 
        else 
        {
            int nDotIndex = strVersion.indexOf(".");
            if (nDotIndex != -1) 
            {
                return Integer.parseInt(strVersion.substring(0, nDotIndex));
            }
            return Integer.parseInt(strVersion);
        }
    }

    public static int getClassSupport() 
    {
        VM vmInstance = VM.constructVM(null);
        int nCurrentJavaVersion = getCurrentJavaVersion();
        int nMaxClassVersion = 44 + nCurrentJavaVersion;
        
        System.out.println("Current Java version: " + nCurrentJavaVersion);
        System.out.println("Corresponding class file version: " + nMaxClassVersion);
        
        int nSupportedVersion = -1;
        try 
        {
            for (int i = 49; i <= nMaxClassVersion + 5; i++) 
            {
                ClassNode clsNode = new ClassNode();
                clsNode.version = i;
                clsNode.name = "TestClass" + i;
                clsNode.superName = "java/lang/Object";
                
                vmInstance.explicitlyPreload(clsNode);
                if (vmInstance.loadClass(clsNode.name) == null) 
                {
                    System.out.println("VM does not support class version: " + i);
                    nSupportedVersion = i - 1;
                    break;
                } 
                else 
                {
                    nSupportedVersion = i;
                    System.out.println("VM supports class version: " + i);
                }
            }
        } 
        catch (Exception e) 
        {
            System.err.println("Error during testing: " + e.getMessage());
        }
        
        return nSupportedVersion;
    }
}