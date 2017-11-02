package me.nov.zkmstrings;

import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import me.lpk.analysis.Sandbox;
import me.lpk.util.AccessHelper;
import me.nov.zkmstrings.utils.InstructionUtils;
import me.nov.zkmstrings.utils.ZKMUtils;

public class Deobfuscation implements Opcodes {

  private Map<String, ClassNode> classes;
  private boolean success;
  
  /**
   * Disable if there are 2 stringarrays or there isn't a method with two ints as param (and returning a string)
   */
  public final static boolean NO_SCND_METHOD = false;
  
  public final static boolean REMOVE_STATICINVK = false;
  
  public final static boolean FORCE_GUESS = false;
  
  public Deobfuscation(Map<String, ClassNode> classes) {
    this.classes = classes;
    this.success = false;
  }

  public boolean isSuccess() {
    return success;
  }

  public void start() {
    try {
      PrintWriter pw = new PrintWriter("strings.txt");
      for (ClassNode cn : classes.values()) {
        ClassNode invocationNode = ZKMUtils.generateInvocation(cn);
        if (invocationNode == null || invocationNode.methods.size() < (NO_SCND_METHOD ? 1 : 2)) {
          continue;
        }
        Class<?> loaded = null;
        try {
          loaded = Sandbox.load(invocationNode);
          Method clinit = loaded.getMethod("init_zkm");
          clinit.invoke(null); // invoke decryption
        } catch (Exception e) {
          e.printStackTrace();
          System.out.println(e.toString() + " at " + cn.name);
          if(e.getCause() != null) {
            Throwable t = e.getCause();
            System.out.println("caused by " + t.toString() + ((t instanceof NoSuchFieldError) ? " (disable NO_SCND_METHOD?)" : ""));
          }
          continue;
        }
        if (NO_SCND_METHOD) {
          //code for versions older than zkm 8
          String[] decrypted = null;
          Field array = loaded.getDeclaredField(invocationNode.fields.get(0).name);
          decrypted = (String[]) array.get(null);
          if (decrypted != null) {
            for (MethodNode mn : cn.methods) { // find decrypt calls
              for (AbstractInsnNode ain : mn.instructions.toArray()) {
                if (ain.getOpcode() == GETSTATIC) {
                  FieldInsnNode fin = (FieldInsnNode) ain;
                  if (fin.name.equals(array.getName()) && fin.desc.equals("[Ljava/lang/String;")) {
                    AbstractInsnNode next = fin.getNext();
                    while (next != null && next instanceof VarInsnNode) {
                      next = next.getNext();
                    }
                    if (next != null && InstructionUtils.isNumber(next) && next.getNext().getOpcode() == AALOAD) {
                      int indx = InstructionUtils.getIntValue(next);
                      AbstractInsnNode aaload = next.getNext();
                      mn.instructions.insert(aaload, new LdcInsnNode(decrypted[indx]));
                      pw.println(cn.name + "." + mn.name + mn.desc + ": " + decrypted[indx]);
                      mn.instructions.insert(aaload, new InsnNode(POP));
                    }
                  }
                }
              }
            }
          }
          continue;
        }

        //code for version 8+
        Method decrypt = loaded.getMethod("decrypt_array", new Class[] { int.class, int.class });
        for (MethodNode mn : cn.methods) { // find decrypt calls
          for (AbstractInsnNode ain : mn.instructions.toArray()) {
            if (ain.getOpcode() == INVOKESTATIC) {
              MethodInsnNode min = (MethodInsnNode) ain;
              if (min.desc.equals("(II)Ljava/lang/String;") && min.owner.equals(cn.name) && InstructionUtils.isNumber(min.getPrevious())
                  && InstructionUtils.isNumber(min.getPrevious().getPrevious())) {
                int nr1 = InstructionUtils.getIntValue(min.getPrevious().getPrevious());
                int nr2 = InstructionUtils.getIntValue(min.getPrevious());
                String decryptedStr = (String) decrypt.invoke(null, nr1, nr2);
                if (decryptedStr != null) {
                  mn.instructions.remove(min.getPrevious().getPrevious());
                  mn.instructions.remove(min.getPrevious());
                  mn.instructions.set(ain, new LdcInsnNode(decryptedStr));
                  System.out.println(decryptedStr);
                }
                pw.println(decryptedStr);
              }
            }
          }
        }
      }
      success = true;
      pw.close();
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }

}
