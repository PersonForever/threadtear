package me.nov.threadtear.execution.zkm;

import me.nov.threadtear.analysis.stack.ConstantValue;
import me.nov.threadtear.analysis.stack.IConstantReferenceHandler;
import me.nov.threadtear.execution.Clazz;
import me.nov.threadtear.execution.Execution;
import me.nov.threadtear.execution.ExecutionCategory;
import me.nov.threadtear.execution.ExecutionTag;
import me.nov.threadtear.util.asm.Access;
import me.nov.threadtear.util.asm.InstructionModifier;
import me.nov.threadtear.util.asm.Instructions;
import me.nov.threadtear.util.asm.References;
import me.nov.threadtear.util.reflection.DynamicReflection;
import me.nov.threadtear.vm.IVMReferenceHandler;
import me.nov.threadtear.vm.Sandbox;
import me.nov.threadtear.vm.VM;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import javax.crypto.BadPaddingException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandleInfo;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static org.objectweb.asm.Opcodes.*;

public class DESObfuscationZKM extends Execution implements IVMReferenceHandler, IConstantReferenceHandler
{
    private static final String ZKM_INVOKEDYNAMIC_HANDLE_DESC = "(Ljava/lang/invoke/MethodHandles$Lookup;" +
            "Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;";
    private static final String ZKM_STRING_INVOKEDYNAMIC_DESC = "\\([IJ]+\\)Ljava/lang/String;";
    private static final String ZKM_INVOKEDYNAMIC_REAL_BOOTSTRAP_DESC_REGEX = "\\(Ljava/lang/invoke/MethodHandles" +
            "\\$Lookup;Ljava/lang/invoke/MutableCallSite;Ljava/lang/String;Ljava/lang/invoke/MethodType;[JI]+\\)" +
            "Ljava/lang/invoke/MethodHandle;";
    private static final String ZKM_REFERENCE_DESC_REGEX = "\\((?:L.*;)?J+\\)(?:\\[?(?:I|J|(?:L.*;)))";

    private static final String[] COMMON_DEPENDENCIES = {
            "xxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxx"
    };

    private boolean verboseMode;
    private int decryptedStringsCount;
    private int encryptedStringsCount;
    private int decryptedReferencesCount;
    private int encryptedReferencesCount;
    private Map<String, Clazz> classMap;

    public DESObfuscationZKM()
    {
        super(ExecutionCategory.ZKM, "ZKM DES Deobfuscator",
                "Deobfuscates string / access obfuscation with DES cipher." +
                        "<br>XinXinFucker",
                ExecutionTag.POSSIBLE_DAMAGE,
                ExecutionTag.POSSIBLY_MALICIOUS);
    }

    @Override
    public boolean execute(Map<String, Clazz> classes, boolean verbose)
    {
        this.verboseMode = verbose;
        this.decryptedReferencesCount = 0;
        this.encryptedReferencesCount = 0;
        this.decryptedStringsCount = 0;
        this.encryptedStringsCount = 0;
        this.classMap = classes;

        logger.info("Starting ZKM DES universal deobfuscation...");

        logger.info("Phase 1: Decrypting references...");
        List<Clazz> classList = new ArrayList<>(classes.values());
        int totalClassCount = classList.size();
        int processedClassCount = 0;

        for (Clazz clazz : classList)
        {
            processedClassCount++;
            if (verboseMode)
            {
                logger.info("Processing class {}/{}: {}", processedClassCount, totalClassCount, clazz.node.name);
            }
            try
            {
                decryptReferences(clazz);
            }
            catch (Exception e)
            {
                logger.warning("Failed to decrypt references for {}: {}", clazz.node.name, e.getMessage());
            }
        }

        logger.info("Phase 2: Decrypting strings...");
        processedClassCount = 0;
        for (Clazz clazz : classList)
        {
            processedClassCount++;
            if (verboseMode)
            {
                logger.info("Processing class {}/{}: {}", processedClassCount, totalClassCount, clazz.node.name);
            }
            try
            {
                decryptStrings(clazz);
            }
            catch (Exception e)
            {
                logger.warning("Failed to decrypt strings for {}: {}", clazz.node.name, e.getMessage());
            }
        }

        int stringSuccessRate = encryptedStringsCount > 0 ? Math.round((this.decryptedStringsCount / (float) this.encryptedStringsCount) * 100) : 0;
        int referenceSuccessRate = encryptedReferencesCount > 0 ? Math.round((this.decryptedReferencesCount / (float) this.encryptedReferencesCount) * 100) : 0;

        int totalEncrypted = encryptedStringsCount + encryptedReferencesCount;
        int totalDecrypted = decryptedStringsCount + decryptedReferencesCount;
        int totalSuccessRate = totalEncrypted > 0 ? Math.round((totalDecrypted / (float) totalEncrypted) * 100) : 0;

        logger.info("DECRYPTION COMPLETE");
        logger.info("Strings: {}/{} ({}% success)", decryptedStringsCount, encryptedStringsCount, stringSuccessRate);
        logger.info("References: {}/{} ({}% success)", decryptedReferencesCount, encryptedReferencesCount, referenceSuccessRate);
        logger.info("Total: {}/{} ({}% success)", totalDecrypted, totalEncrypted, totalSuccessRate);

        return decryptedReferencesCount > 0 || decryptedStringsCount > 0;
    }

    private void decryptStrings(Clazz clazz)
    {
        ClassNode classNode = clazz.node;
        logger.info("Starting string decryption for class: {}", classNode.name);

        int classStringSuccessCount = 0;
        int classStringTotalCount = 0;
        int classStringFailCount = 0;

        for (MethodNode methodNode : classNode.methods)
        {
            InsnList instructions = methodNode.instructions;
            Set<InvokeDynamicInsnNode> stringNodes = getInvokeDynamicInstructions(
                    methodNode, node -> node.desc.matches(ZKM_STRING_INVOKEDYNAMIC_DESC)
            );

            if (stringNodes.isEmpty())
            {
                continue;
            }

            classStringTotalCount += stringNodes.size();
            InstructionModifier modifier = new InstructionModifier();

            for (InvokeDynamicInsnNode node : stringNodes)
            {
                boolean success = false;
                String decryptedString = null;

                try
                {
                    VM vm = createEnhancedVM();
                    long keyValue = getStringFieldKey(classNode, node, instructions, vm);

                    if (keyValue == -1)
                    {
                        logger.warning("Key extraction failed for string in {}.{}", classNode.name, methodNode.name);
                        classStringFailCount++;
                        continue;
                    }

                    Handle bsm = node.bsm;
                    Class<?> bootstrapClass = vm.loadClass(bsm.getOwner().replace("/", "."));

                    Method stringDecryptionMethod = findStringDecryptionMethod(bootstrapClass);
                    if (stringDecryptionMethod == null)
                    {
                        logger.warning("String decryption method not found in {}", bsm.getOwner());
                        classStringFailCount++;
                        continue;
                    }

                    stringDecryptionMethod.setAccessible(true);

                    StringDecryptionParams params = extractStringDecryptionParams(node);
                    if (params.firstParameter == null || params.secondParameter == null)
                    {
                        logger.warning("Could not find string decryption parameters in {}.{}", classNode.name, methodNode.name);
                        classStringFailCount++;
                        continue;
                    }

                    long finalSecondParam = params.secondParameter ^ keyValue;
                    decryptedString = invokeStringDecryption(stringDecryptionMethod, params.firstParameter, finalSecondParam);

                    if (decryptedString != null && !decryptedString.isEmpty())
                    {
                        replaceStringDecryption(node, modifier, decryptedString);
                        classStringSuccessCount++;
                        decryptedStringsCount++;
                        success = true;
                        logger.info("STRING DECRYPTION SUCCESS: {}.{} -> '{}'", 
                                classNode.name, methodNode.name, 
                                truncateString(decryptedString, 100));
                    }
                    else
                    {
                        classStringFailCount++;
                        logger.warning("STRING DECRYPTION FAILED: {}.{} - Decryption returned null or empty", 
                                classNode.name, methodNode.name);
                    }

                }
                catch (ExceptionInInitializerError e)
                {
                    classStringFailCount++;
                    logger.warning("STRING DECRYPTION ERROR: {}.{} - Class initialization failed: {}", 
                            classNode.name, methodNode.name, e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
                    continue;
                }
                catch (Exception e)
                {
                    classStringFailCount++;
                    logger.warning("STRING DECRYPTION ERROR: {}.{} - {}", 
                            classNode.name, methodNode.name, e.getMessage());
                    if (verboseMode)
                    {
                        logger.debug("Detailed error:", e);
                    }
                }
            }

            modifier.apply(methodNode);
            
            if (!stringNodes.isEmpty())
            {
                int methodSuccess = classStringSuccessCount;
                int methodTotal = stringNodes.size();
                logger.info("Method {}.{} string summary: {}/{} decrypted", 
                        classNode.name, methodNode.name, methodSuccess, methodTotal);
            }
        }

        if (classStringTotalCount > 0)
        {
            int successRate = Math.round((classStringSuccessCount / (float) classStringTotalCount) * 100);
            logger.info("Class {} string summary: {}/{} successful ({}%)", 
                    classNode.name, classStringSuccessCount, classStringTotalCount, successRate);
        }
        else
        {
            logger.info("Class {}: No encrypted strings found", classNode.name);
        }

        encryptedStringsCount += classStringTotalCount;
    }

    private Method findStringDecryptionMethod(Class<?> bootstrapClass)
    {
        return Arrays.stream(bootstrapClass.getDeclaredMethods())
                .filter(method -> method.getParameterCount() == 2)
                .filter(method ->
                {
                    Class<?>[] paramTypes = method.getParameterTypes();
                    return (paramTypes[0] == int.class && paramTypes[1] == long.class) ||
                            (paramTypes[0] == long.class && paramTypes[1] == long.class);
                })
                .findFirst()
                .orElse(null);
    }

    private static class StringDecryptionParams
    {
        Integer firstParameter;
        Long secondParameter;
    }

    private StringDecryptionParams extractStringDecryptionParams(InvokeDynamicInsnNode node)
    {
        StringDecryptionParams params = new StringDecryptionParams();
        AbstractInsnNode current = node.getPrevious();

        for (int i = 0; i < 5 && current != null; i++, current = current.getPrevious())
        {
            if (current.getOpcode() == SIPUSH || current.getOpcode() == BIPUSH)
            {
                params.firstParameter = (int) ((IntInsnNode) current).operand;
            }
            else if (current.getOpcode() == LDC && ((LdcInsnNode) current).cst instanceof Long)
            {
                params.secondParameter = (Long) ((LdcInsnNode) current).cst;
            }

            if (params.firstParameter != null && params.secondParameter != null)
            {
                break;
            }
        }

        return params;
    }

    private String invokeStringDecryption(Method stringDecryptionMethod, Integer firstParam, long secondParam)
    {
        try
        {
            Object result;
            if (stringDecryptionMethod.getParameterTypes()[0] == int.class)
            {
                result = stringDecryptionMethod.invoke(null, firstParam, secondParam);
            }
            else
            {
                result = stringDecryptionMethod.invoke(null, (long) firstParam, secondParam);
            }
            
            if (result instanceof String)
            {
                return (String) result;
            }
            return null;
        }
        catch (InvocationTargetException e)
        {
            Throwable cause = e.getCause();
            if (cause instanceof ExceptionInInitializerError)
            {
                throw (ExceptionInInitializerError) cause;
            }
            logger.debug("String decryption invocation failed: {}", cause.getMessage());
            return null;
        }
        catch (Exception e)
        {
            logger.debug("String decryption method invocation failed: {}", e.getMessage());
            return null;
        }
    }

    private void replaceStringDecryption(InvokeDynamicInsnNode node, InstructionModifier modifier, String decryptedString)
    {
        AbstractInsnNode current = node.getPrevious();
        for (int i = 0; i < 2 && current != null; i++)
        {
            AbstractInsnNode prev = current.getPrevious();
            if (current.getOpcode() == SIPUSH || current.getOpcode() == BIPUSH || 
                (current.getOpcode() == LDC && ((LdcInsnNode) current).cst instanceof Long))
            {
                modifier.remove(current);
            }
            current = prev;
        }

        modifier.replace(node, new LdcInsnNode(decryptedString));
    }

    private void decryptReferences(Clazz clazz)
    {
        logger.collectErrors(clazz);
        ClassNode classNode = clazz.node;
        logger.info("Starting reference decryption for class: {}", classNode.name);

        MethodNode clinit = super.getStaticInitializer(classNode);
        if (clinit != null)
        {
            BiPredicate<String, String> predicate = (owner, desc) -> !owner.equals(classNode.name)
                && !owner.matches("javax?/(lang|util|crypto)/.*")
                && !desc.matches("\\[?Ljava/lang/String;|J")
                && !desc.matches("\\(JJLjava/lang/Object;\\)L.+;")
                && !desc.equals("(J)J")
                && !desc.matches(ZKM_REFERENCE_DESC_REGEX);
            Instructions.isolateCallsThatMatch(clinit, predicate, predicate);
        }
        
        if (clinit == null)
        {
            logger.info("Skipping class {} - no static initializer found", classNode.name);
            return;
        }
            
        ClassNode proxyNode = createEnhancedProxy(classNode, clinit);
        if (proxyNode == null)
        {
            logger.warning("Failed to create proxy for {}", classNode.name);
            return;
        }

        Map<String, String> singleMap = Collections.singletonMap(classNode.name, proxyNode.name);
        proxyNode.methods.stream()
                .map(m -> m.instructions.toArray())
                .flatMap(Arrays::stream)
                .forEach(ain -> References.remapClassRefs(singleMap, ain));
        proxyNode.fields.forEach(fieldNode -> References.remapFieldType(singleMap, fieldNode));

        VM vm = createEnhancedVM();
        if (!initializeProxy(classNode, proxyNode, vm))
        {
            logger.warning("Failed to initialize proxy for {}", classNode.name);
            return;
        }

        int classReferenceSuccessCount = 0;
        int classReferenceTotalCount = 0;

        for (MethodNode methodNode : classNode.methods)
        {
            if (methodNode.name.equals("clinitProxy"))
            {
                methodNode.name = "<clinit>";
            }

            Set<InvokeDynamicInsnNode> referenceNodes = invokeDynamicsWithoutStrings(methodNode);
            if (referenceNodes.isEmpty())
            {
                continue;
            }

            if (verboseMode)
            {
                logger.debug("Found {} encrypted references in {}.{}", referenceNodes.size(), classNode.name, methodNode.name);
            }
            
            classReferenceTotalCount += referenceNodes.size();
            InsnList instructions = methodNode.instructions;
            InstructionModifier modifier = new InstructionModifier();
            Frame<ConstantValue>[] frames = getConstantFrames(classNode, methodNode, this);
            long keyValue = 0;
            int methodSuccessCount = 0;

            for (InvokeDynamicInsnNode node : referenceNodes)
            {
                boolean success = false;
                String referenceInfo = null;

                try
                {
                    if (keyValue == 0)
                    {
                        keyValue = getFieldKey(proxyNode, node, instructions, vm);
                    }
                    if (keyValue == -1)
                    {
                        logger.warning("Key extraction failed for {}.{}", classNode.name, methodNode.name);
                        continue;
                    }

                    Handle bsm = node.bsm;
                    Class<?> bootstrapClass = vm.loadClass(bsm.getOwner().replace("/", "."));
                    Method bootstrapMethod = findBootstrapMethod(bootstrapClass);

                    if (bootstrapMethod == null)
                    {
                        logger.warning("Bootstrap method not found in {}", bsm.getOwner());
                        continue;
                    }

                    bootstrapMethod.setAccessible(true);

                    int nodeIndex = instructions.indexOf(node);
                    if (nodeIndex < 0 || nodeIndex >= frames.length)
                    {
                        logger.warning("Frame index out of bounds for {}.{}", classNode.name, methodNode.name);
                        continue;
                    }
                    
                    Frame<ConstantValue> frame = frames[nodeIndex];
                    
                    List<Object> argsList = new ArrayList<>(Arrays.asList(
                        DynamicReflection.getTrustedLookup(), null, node.name,
                        MethodType.fromMethodDescriptorString(node.desc, vm)
                    ));

                    int parameterCount = Type.getArgumentTypes(Type.getMethodDescriptor(bootstrapMethod)).length - 4;
                    for (int i = 0; i < parameterCount - 1; i++)
                    {
                        ConstantValue constantValue = frame.getStack(frame.getStackSize() - parameterCount + i);
                        if (!constantValue.isKnown())
                        {
                            logger.warning("Unknown stack value at depth {} in {}.{}", i, classNode.name, methodNode.name);
                            throw new IllegalStateException("Unknown stack value at depth " + i);
                        }
                        argsList.add(constantValue.getValue());
                    }
                    argsList.add(keyValue);

                    MethodHandle methodHandle;
                    try
                    {
                        methodHandle = (MethodHandle) bootstrapMethod.invoke(null, argsList.toArray());
                    }
                    catch (InvocationTargetException e)
                    {
                        Throwable cause = e.getCause();
                        if (verboseMode)
                        {
                            logger.error("Exception during bootstrap invocation", e);
                        }
                        if (cause instanceof ArrayIndexOutOfBoundsException)
                        {
                            logger.warning("Array index issue in bootstrap method for {}.{}", classNode.name, methodNode.name);
                            continue;
                        }
                        logger.warning("Failed to get MethodHandle in {}.{}: {}", classNode.name, methodNode.name, shortStacktrace(cause));
                        continue;
                    }
                    
                    MethodHandleInfo methodHandleInfo = DynamicReflection.revealMethodInfo(methodHandle);
                    AbstractInsnNode instruction = DynamicReflection.getInstructionFromHandleInfo(methodHandleInfo);

                    if (instruction == null)
                    {
                        logger.warning("No instruction generated for {}.{}", classNode.name, methodNode.name);
                        continue;
                    }

                    modifier.replace(node, new InsnNode(POP2), new InsnNode(POP2), instruction);
                    classReferenceSuccessCount++;
                    methodSuccessCount++;
                    decryptedReferencesCount++;
                    success = true;

                    referenceInfo = String.format("%s.%s%s", 
                            methodHandleInfo.getDeclaringClass().getName(),
                            methodHandleInfo.getName(),
                            methodHandleInfo.getMethodType());

                    logger.info("REFERENCE DECRYPTION SUCCESS: {}.{} -> {}", classNode.name, methodNode.name, referenceInfo);

                }
                catch (IncompatibleClassChangeError ignored)
                {
                    logger.warning("Incompatible class change in {}.{}", classNode.name, methodNode.name);
                }
                catch (ExceptionInInitializerError | NoClassDefFoundError error)
                {
                    if (verboseMode)
                    {
                        logger.error("Error during class initialization", error);
                    }
                    logger.error("Class initialization failed for {}: {}", classNode.name, error.getMessage());
                }
                catch (Exception e)
                {
                    logger.warning("REFERENCE DECRYPTION ERROR: {}.{} - {}", 
                            classNode.name, methodNode.name, e.getMessage());
                    if (verboseMode)
                    {
                        logger.debug("Detailed error:", e);
                    }
                }
            }

            modifier.apply(methodNode);
            
            logger.info("Method {}.{} reference summary: {}/{} decrypted", 
                    classNode.name, methodNode.name, methodSuccessCount, referenceNodes.size());
        }

        if (classReferenceTotalCount > 0)
        {
            int successRate = Math.round((classReferenceSuccessCount / (float) classReferenceTotalCount) * 100);
            logger.info("Class {} reference summary: {}/{} successful ({}%)", 
                    classNode.name, classReferenceSuccessCount, classReferenceTotalCount, successRate);
        }
        else
        {
            logger.info("Class {}: No encrypted references found", classNode.name);
        }

        encryptedReferencesCount += classReferenceTotalCount;
    }

    private Method findBootstrapMethod(Class<?> bootstrapClass)
    {
        return Arrays.stream(bootstrapClass.getDeclaredMethods())
                .filter(method -> Type.getMethodDescriptor(method).matches(ZKM_INVOKEDYNAMIC_REAL_BOOTSTRAP_DESC_REGEX))
                .findFirst()
                .orElse(null);
    }

    private VM createEnhancedVM()
    {
        try
        {
            VM vm = VM.constructVMWithContextLoader(this);
            //vm.preloadDependencies(COMMON_DEPENDENCIES);
            return vm;
        }
        catch (Exception e)
        {
            logger.warning("Enhanced VM creation failed, using fallback: {}", e.getMessage());
            return VM.constructVM(this);
        }
    }

    private ClassNode createEnhancedProxy(ClassNode classNode, MethodNode clinit)
    {
        if (clinit == null) return null;

        ClassNode proxyClass = Sandbox.createClassProxy(classNode.name);

        proxyClass.access = classNode.access;
        proxyClass.superName = classNode.superName;
        proxyClass.interfaces = new ArrayList<>(classNode.interfaces);
        proxyClass.signature = classNode.signature;

        proxyClass.fields.addAll(classNode.fields.stream()
                .filter(f -> Access.isStatic(f.access))
                .collect(Collectors.toList()));

        Set<MethodNode> methodsToCopy = new HashSet<>();
        
        Arrays.stream(clinit.instructions.toArray())
                .filter(node -> node instanceof MethodInsnNode)
                .map(node -> (MethodInsnNode) node)
                .filter(node -> node.owner.equals(classNode.name))
                .forEach(node ->
                {
                    MethodNode original = getMethod(classNode, node.name, node.desc);
                    if (original != null) methodsToCopy.add(original);
                });

        classNode.methods.stream()
                .filter(m -> Access.isStatic(m.access))
                .forEach(methodsToCopy::add);

        clinit.name = "clinitProxy";
        methodsToCopy.add(clinit);

        proxyClass.methods.addAll(methodsToCopy);
        return proxyClass;
    }

    private boolean initializeProxy(ClassNode classNode, ClassNode proxyNode, VM vm)
    {
        try
        {
            Class<?> clazz = vm.loadClass(classNode.name.replace("/", "."));
            Method clinitProxy = clazz.getMethod("clinitProxy");
            clinitProxy.invoke(null);
            return true;
        }
        catch (InvocationTargetException e)
        {
            Throwable cause = e.getCause();
            if (cause instanceof BadPaddingException)
            {
                logger.warning("Skipping class {} due to decryption key issues", classNode.name);
                return false;
            }
            else if (cause instanceof NullPointerException)
            {
                logger.debug("NPE during proxy initialization in {} (expected)", classNode.name);
                return true;
            }
            else
            {
                logger.warning("Proxy initialization failed for {}: {}", classNode.name, cause.getMessage());
                return false;
            }
        }
        catch (Exception e)
        {
            logger.warning("Failed to initialize proxy for {}: {}", classNode.name, e.getMessage());
            return false;
        }
    }

    private long getStringFieldKey(ClassNode classNode, InvokeDynamicInsnNode node, InsnList instructions, VM vm)
    {
        try
        {
            MethodNode clinit = getStaticInitializer(classNode);
            if (clinit != null)
            {
                FieldInsnNode fieldNode = findFirstFieldInstruction(clinit);
                if (fieldNode != null)
                {
                    Class<?> clazz = vm.loadClass(classNode.name.replace("/", "."));
                    Field field = clazz.getDeclaredField(fieldNode.name);
                    field.setAccessible(true);
                    return (Long) field.get(null);
                }
            }

            return findKeyByPattern(node, instructions);

        }
        catch (Exception e)
        {
            if (verboseMode)
            {
                logger.debug("String key search failed: {}", e.getMessage());
            }
            return -1;
        }
    }

    private long getFieldKey(ClassNode classNode, InvokeDynamicInsnNode node, InsnList instructions, VM vm)
    {
        try
        {
            VarInsnNode varInsnNode = findKeyVariable(node, instructions);
            if (varInsnNode != null)
            {
                long key = searchForSecondKey(varInsnNode.var, instructions);
                if (key != -1) return key;
            }

            MethodNode clinit = getStaticInitializer(classNode);
            if (clinit != null)
            {
                FieldInsnNode fieldNode = findFirstFieldInstruction(clinit);
                if (fieldNode != null)
                {
                    Class<?> clazz = vm.loadClass(classNode.name.replace("/", "."));
                    Field field = clazz.getDeclaredField(fieldNode.name);
                    field.setAccessible(true);
                    return (Long) field.get(null);
                }
            }

            return findKeyByPattern(node, instructions);

        }
        catch (Exception e)
        {
            if (verboseMode)
            {
                logger.debug("Key search failed: {}", e.getMessage());
            }
            return -1;
        }
    }

    private VarInsnNode findKeyVariable(AbstractInsnNode start, InsnList instructions)
    {
        for (AbstractInsnNode node = start.getPrevious(); node != null; node = node.getPrevious())
        {
            if (node.getOpcode() == LSTORE)
            {
                return (VarInsnNode) node;
            }
        }
        return null;
    }

    private long findKeyByPattern(AbstractInsnNode start, InsnList instructions)
    {
        for (AbstractInsnNode node = start.getPrevious(); node != null; node = node.getPrevious())
        {
            if (node.getOpcode() == LXOR)
            {
                AbstractInsnNode prev1 = node.getPrevious();
                AbstractInsnNode prev2 = prev1 != null ? prev1.getPrevious() : null;

                if (prev2 != null && prev2.getOpcode() == GETSTATIC &&
                        prev1 != null && prev1.getOpcode() == LDC &&
                        ((LdcInsnNode) prev1).cst instanceof Long)
                {
                    return (Long) ((LdcInsnNode) prev1).cst;
                }
            }
        }
        return -1;
    }

    private FieldInsnNode findFirstFieldInstruction(MethodNode clinit)
    {
        for (AbstractInsnNode node : clinit.instructions)
        {
            if (node.getOpcode() != PUTSTATIC)
                continue;
            FieldInsnNode fieldInsnNode = (FieldInsnNode) node;
            if (!fieldInsnNode.desc.equals("J"))
                break;
            return fieldInsnNode;
        }
        return null;
    }

    private long searchForSecondKey(int variableIndex, InsnList instructions)
    {
        for (AbstractInsnNode node : instructions.toArray())
        {
            if (node.getOpcode() != LSTORE)
                continue;
            VarInsnNode varInsnNode = (VarInsnNode) node;
            if (varInsnNode.var != variableIndex)
                continue;
            AbstractInsnNode previous = varInsnNode.getPrevious();
            if (previous == null || previous.getPrevious() == null || !(previous.getPrevious() instanceof LdcInsnNode))
                continue;
            LdcInsnNode ldcInsnNode = (LdcInsnNode) previous.getPrevious();
            return (long) ldcInsnNode.cst;
        }
        return -1;
    }

    private Set<InvokeDynamicInsnNode> invokeDynamicsWithoutStrings(MethodNode methodNode)
    {
        return this.getInvokeDynamicInstructions(methodNode)
                .stream()
                .filter(node -> !node.desc.matches(ZKM_STRING_INVOKEDYNAMIC_DESC))
                .collect(Collectors.toSet());
    }

    private Set<InvokeDynamicInsnNode> getInvokeDynamicInstructions(MethodNode methodNode)
    {
        return this.getInvokeDynamicInstructions(methodNode,
                node -> node.bsm.getDesc().equals(ZKM_INVOKEDYNAMIC_HANDLE_DESC)
        );
    }

    private Set<InvokeDynamicInsnNode> getInvokeDynamicInstructions(
            MethodNode methodNode, Predicate<InvokeDynamicInsnNode> predicate
    )
    {
        if (predicate == null)
            predicate = __ -> true;
        return Arrays.stream(methodNode.instructions.toArray())
                .filter(node -> node.getOpcode() == INVOKEDYNAMIC)
                .map(node -> (InvokeDynamicInsnNode) node)
                .filter(node -> node.bsm != null)
                .filter(node -> !node.bsm.getName().equals("metafactory"))
                .filter(predicate)
                .collect(Collectors.toSet());
    }

    private boolean hasDESEncryption(Clazz c)
    {
        ClassNode cn = c.node;
        if (Access.isInterface(cn.access))
            return false;
        MethodNode mn = getStaticInitializer(cn);
        if (mn == null)
            return false;
        return StreamSupport.stream(mn.instructions.spliterator(), false)
                .anyMatch(ain -> ain.getType() == AbstractInsnNode.LDC_INSN &&
                        "DES/CBC/PKCS5Padding".equals(((LdcInsnNode) ain).cst));
    }

    private String truncateString(String str, int maxLength)
    {
        if (str == null || str.length() <= maxLength)
        {
            return str;
        }
        return str.substring(0, maxLength - 3) + "...";
    }

    @Override
    public String getAuthor()
    {
        return "XinXin_Fucker";
    }

    @Override
    public ClassNode tryClassLoad(String name)
    {
        return this.classMap.containsKey(name) ? this.classMap.get(name).node : null;
    }

    @Override
    public Object getFieldValueOrNull(BasicValue v, String owner, String name, String desc)
    {
        return null;
    }

    @Override
    public Object getMethodReturnOrNull(BasicValue v, String owner, String name, String desc, List<? extends ConstantValue> values)
    {
        return null;
    }
}