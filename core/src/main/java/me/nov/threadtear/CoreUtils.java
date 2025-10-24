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
        catch (NullPointerException npe)
        {
            return "(dev)";
        }
    }

    public static boolean isNoverify()
    {
        RuntimeMXBean rtmxBean = ManagementFactory.getRuntimeMXBean();
        List<String> lstArgs = rtmxBean.getInputArguments();
        return lstArgs.stream().anyMatch(sArg -> sArg.contains("-Xverify:none") || sArg.contains("-noverify"));
    }

    public static boolean isAttachable()
    {
        try
        {
            Class.forName("com.sun.tools.attach.VirtualMachine");
            return true;
        }
        catch (Throwable t)
        {
            return false;
        }
    }

    public static int getClassSupport()
    {
        VM vmVM = VM.constructVM(null);
        int nLastSupported = -1;
        int nMinMajor = 49;
        int nMaxMajor = 70;

        try
        {
            for (int nMajor = nMinMajor; nMajor <= nMaxMajor; nMajor++)
            {
                ClassNode cnNode = new ClassNode();
                cnNode.version = nMajor;
                cnNode.name = "v" + nMajor;
                cnNode.superName = "java/lang/Object";
                vmVM.explicitlyPreload(cnNode);

                if (vmVM.loadClass(cnNode.name) == null)
                    break;

                nLastSupported = nMajor;
            }
        }
        catch (Exception e)
        {
            // ignore
        }

        return nLastSupported;
    }
}
