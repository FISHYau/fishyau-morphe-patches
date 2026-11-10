import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Targeted original DEX evidence; never loads application classes. */
class InspectDex {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) throw new IllegalArgumentException("input.apk NEW_OUTPUT.txt Lowner;->method(params)return ...");
        Path output = Path.of(args[1]);
        Set<String> targets = new LinkedHashSet<>(Arrays.asList(args).subList(2, args.length));
        for (String target : targets)
            if (!target.startsWith("L") || !target.contains(";->") || !target.contains("("))
                throw new IllegalArgumentException("Full DEX descriptor required: " + target);
        Map<String, Integer> found = new HashMap<>();
        var container = DexFileFactory.loadDexContainer(new File(args[0]), Opcodes.forApi(36));
        try (var out = new PrintWriter(Files.newBufferedWriter(output, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW))) {
            for (String dexName : container.getDexEntryNames()) {
                for (ClassDef cls : container.getEntry(dexName).getDexFile().getClasses()) {
                    if (targets.stream().noneMatch(t -> t.startsWith(cls.getType() + "->"))) continue;
                    for (Method method : cls.getMethods()) {
                        String key = cls.getType() + "->" + method.getName() + "(" + String.join("", method.getParameterTypes()) + ")" + method.getReturnType();
                        if (!targets.contains(key)) continue;
                        found.merge(key, 1, Integer::sum);
                        out.println("\nDEX " + dexName + " METHOD " + key);
                        out.println("flags=0x" + Integer.toHexString(method.getAccessFlags()));
                        var body = method.getImplementation();
                        if (body == null) { out.println("NO CODE"); continue; }
                        out.println("registers=" + body.getRegisterCount() + " tries=" + body.getTryBlocks().size());
                        int offset = 0;
                        for (Instruction ins : body.getInstructions()) {
                            out.printf("%04x %-25s", offset, ins.getOpcode().name());
                            if (ins instanceof RegisterRangeInstruction r) out.print(" v" + r.getStartRegister() + ".. count=" + r.getRegisterCount());
                            else if (ins instanceof FiveRegisterInstruction r) out.print(" {" + r.getRegisterC()+","+r.getRegisterD()+","+r.getRegisterE()+","+r.getRegisterF()+","+r.getRegisterG()+"} count="+r.getRegisterCount());
                            else if (ins instanceof ThreeRegisterInstruction r) out.print(" v"+r.getRegisterA()+", v"+r.getRegisterB()+", v"+r.getRegisterC());
                            else if (ins instanceof TwoRegisterInstruction r) out.print(" v"+r.getRegisterA()+", v"+r.getRegisterB());
                            else if (ins instanceof OneRegisterInstruction r) out.print(" v"+r.getRegisterA());
                            if (ins instanceof ReferenceInstruction r) out.print(" " + r.getReference());
                            if (ins instanceof WideLiteralInstruction l) out.print(" #" + l.getWideLiteral());
                            if (ins instanceof OffsetInstruction b) out.printf(" ->%04x", offset + b.getCodeOffset());
                            out.println();
                            offset += ins.getCodeUnits();
                        }
                    }
                }
            }
            for (String target : targets) out.println("TARGET_COUNT " + found.getOrDefault(target, 0) + " " + target);
        }
        if (targets.stream().anyMatch(t -> found.getOrDefault(t, 0) != 1))
            throw new IllegalStateException("Each target must resolve exactly once; see " + output);
        System.out.println("Read-only DEX inspection: " + found.size() + " exact targets -> " + output);
    }
}
