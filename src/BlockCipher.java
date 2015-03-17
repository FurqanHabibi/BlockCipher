import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import javax.swing.JFileChooser;


public class BlockCipher {

	public static void main(String[] args) {
		BlockCipher cipher = new BlockCipher();
//		Scanner sc = new Scanner(System.in);
//		
//		System.out.println("Welcome to BlockCipher! Please choose encryption or decryption!");
//		System.out.println("1. Encryption");
//		System.out.println("2. Decryption");
//		boolean isEncryption = (sc.nextInt()==1);
//		cipher.setIsEncryption(isEncryption);
//		
//		if (isEncryption) {
//			System.out.println("Please press enter to choose plaintext file!");
//		}
//		else {
//			System.out.println("Please press enter to choose ciphertext file!");
//		}
//		sc.nextLine();
//		cipher.readInput();
//		
//		System.out.println("Please choose mode of operation!");
//		System.out.println("1. ECB");
//		System.out.println("2. CBC");
//		System.out.println("3. CFB 8-bit");
//		System.out.println("Mode of operation :");
//		int mode = (sc.nextInt()%3)+1;
//		
//		System.out.println("Please type in the key :");
//		String keyString = sc.nextLine();
//		cipher.setKey(keyString);
//		
//		if (isEncryption) {
//			System.out.println("Encryption process started...");
//		}
//		else {
//			System.out.println("Decryption process started...");
//		}
//		switch (mode) {
//		case 1:
//			cipher.ECB();
//			break;
//		case 2:
//			cipher.CBC();
//			break;
//		case 3:
//			cipher.CFB();
//			break;
//		}
//		
//		if (isEncryption) {
//			System.out.println("Encryption process finished!.");
//		}
//		else {
//			System.out.println("Decryption process finished!");
//		}
//		cipher.saveOutput();
		
		cipher.setKey("tes");
		
		byte[] tes = new byte[32];
		for (int i=0; i<32; i++) {
			tes[i] = (byte)(i*5);
		}
		System.out.println(Arrays.toString(tes));
		
		cipher.encrypt(tes, 0, tes, 0);
		cipher.decrypt(tes, 0, tes, 0);
		System.out.println(Arrays.toString(tes));
	}
	
	private Rijndael rijndael;
	private Serpent serpent;
	
	private byte[] input;
	private byte[] output;
	private byte[] key;
	private byte[] IV;
	
	private boolean isEncryption;
	
	JFileChooser fileChooser;
	
	public BlockCipher() {
		IV = new byte[16];
		Random random = new Random(0);
		for (int i=0; i<16; i++) {
			IV[i] = (byte)(random.nextInt() % 255);
		}
		
		fileChooser = new JFileChooser();
	}
	
	public void setKey(String keyString) {
		key = new byte[16];
		byte[] keyTemp = keyString.getBytes(StandardCharsets.UTF_8);
		int keyTempLength = Math.min(keyTemp.length, 16);
		System.arraycopy(keyTemp, 0, key, 16-keyTempLength, keyTempLength);

		rijndael = new Rijndael(key);
		serpent = new Serpent(key);
	}
	
	public void setIsEncryption(boolean isEncryption) {
		this.isEncryption = isEncryption;
	}
	
	public void encrypt(byte[] in, int inOff, byte[] out, int outOff) {
		byte[] L = new byte[16];
		byte[] R = new byte[16];
		byte[] temp = new byte[16];
		
		System.arraycopy(in, inOff, L, 0, 16);
		System.arraycopy(in, inOff+16, R, 0, 16);
		
//		System.out.println("###############ENCRYPTION#############");
//		System.out.print(Arrays.toString(L));
//		System.out.println(Arrays.toString(R));
		
		for (int i=0; i<16; i++) {
			System.arraycopy(L, 0, temp, 0, 16);
			System.arraycopy(R, 0, L, 0, 16);
			rijndael.encryptRound(R, 0, R, 0, i);
			for (int j=0; j<16; j++) {
				R[j] ^= temp[j];
			}
//			System.out.print(Arrays.toString(L));
//			System.out.println(Arrays.toString(R));
			
			System.arraycopy(L, 0, temp, 0, 16);
			System.arraycopy(R, 0, L, 0, 16);
			serpent.encryptRound(R, 0, R, 0, i);
			for (int j=0; j<16; j++) {
				R[j] ^= temp[j];
			}
//			System.out.print(Arrays.toString(L));
//			System.out.println(Arrays.toString(R));
		}
		
//		System.out.println();
		
		System.arraycopy(L, 0, out, 0, 16);
		System.arraycopy(R, 0, out, 16, 16);
	}
	
	public void decrypt(byte[] in, int inOff, byte[] out, int outOff) {
		byte[] L = new byte[16];
		byte[] R = new byte[16];
		byte[] temp = new byte[16];
		
		System.arraycopy(in, inOff, L, 0, 16);
		System.arraycopy(in, inOff+16, R, 0, 16);
		
//		System.out.println("###############DECRYPTION#############");
//		System.out.print(Arrays.toString(L));
//		System.out.println(Arrays.toString(R));
		
		for (int i=15; i>=0; i--) {
			System.arraycopy(R, 0, temp, 0, 16);
			System.arraycopy(L, 0, R, 0, 16);
			serpent.encryptRound(L, 0, L, 0, i);
			for (int j=0; j<16; j++) {
				L[j] ^= temp[j];
			}
//			System.out.print(Arrays.toString(L));
//			System.out.println(Arrays.toString(R));
			
			System.arraycopy(R, 0, temp, 0, 16);
			System.arraycopy(L, 0, R, 0, 16);
			rijndael.encryptRound(L, 0, L, 0, i);
			for (int j=0; j<16; j++) {
				L[j] ^= temp[j];
			}
//			System.out.print(Arrays.toString(L));
//			System.out.println(Arrays.toString(R));
		}
		
//		System.out.println();
		
		System.arraycopy(L, 0, out, 0, 16);
		System.arraycopy(R, 0, out, 16, 16);
	}
	
	public void ECB() {
		if (isEncryption) {
//			byte[] length = (Integer.toString(input.length)+"#").getBytes(StandardCharsets.UTF_8);
//			
//			
//			byte[] dirtyStegoBytes = Arrays.copyOf(fileProp, fileProp.length+stegoBytes.length);
//			System.arraycopy(stegoBytes, 0, dirtyStegoBytes, fileProp.length, stegoBytes.length);
		}
		else {
			
		}
	}
	
	public void CBC() {
		
	}
	
	public void CFB() {
		
	}
	
	public void readInput() {
		if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			File file = fileChooser.getSelectedFile();
			try {
				input = Files.readAllBytes(file.toPath());
				output = new byte[input.length];
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}
	
	public void saveOutput() {
		if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
			File file = fileChooser.getSelectedFile();
			try {
				Files.write(file.toPath(), output);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

}
