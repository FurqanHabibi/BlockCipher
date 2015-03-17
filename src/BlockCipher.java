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
		Scanner sc = new Scanner(System.in);
		
		System.out.println("Welcome to BlockCipher! Please choose encryption or decryption!");
		System.out.println("1. Encryption");
		System.out.println("2. Decryption");
		boolean isEncryption = (sc.nextInt()==1);
		sc.nextLine();
		cipher.setIsEncryption(isEncryption);
		
		if (isEncryption) {
			System.out.println("Please press enter to choose plaintext file!");
		}
		else {
			System.out.println("Please press enter to choose ciphertext file!");
		}
		sc.nextLine();
		cipher.readInput();
		
		System.out.println("Please choose mode of operation!");
		System.out.println("1. ECB");
		System.out.println("2. CBC");
		System.out.println("3. CFB 8-bit");
		System.out.println("Mode of operation :");
		int mode = sc.nextInt();
		sc.nextLine();
		
		System.out.println("Please type in the key :");
		String keyString = sc.nextLine();
		cipher.setKey(keyString);
		
		if (isEncryption) {
			System.out.println("Encryption process started...");
		}
		else {
			System.out.println("Decryption process started...");
		}
		switch (mode) {
		case 1:
			cipher.ECB();
			break;
		case 2:
			cipher.CBC();
			break;
		case 3:
			cipher.CFB();
			break;
		}
		
		if (isEncryption) {
			System.out.println("Encryption process finished!");
		}
		else {
			System.out.println("Decryption process finished!");
		}
		cipher.saveOutput();
		
//		cipher.setKey("tes");
//		
//		byte[] tes = new byte[32];
//		for (int i=0; i<32; i++) {
//			tes[i] = (byte)(i*5);
//		}
//		System.out.println(Arrays.toString(tes));
//		
//		cipher.encrypt(tes, 0, tes, 0);
//		cipher.decrypt(tes, 0, tes, 0);
//		System.out.println(Arrays.toString(tes));
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
		
		for (int i=0; i<16; i++) {
			System.arraycopy(L, 0, temp, 0, 16);
			System.arraycopy(R, 0, L, 0, 16);
			rijndael.encryptRound(R, 0, R, 0, i);
			for (int j=0; j<16; j++) {
				R[j] ^= temp[j];
			}
			
			System.arraycopy(L, 0, temp, 0, 16);
			System.arraycopy(R, 0, L, 0, 16);
			serpent.encryptRound(R, 0, R, 0, i);
			for (int j=0; j<16; j++) {
				R[j] ^= temp[j];
			}
		}
		
		System.arraycopy(L, 0, out, outOff, 16);
		System.arraycopy(R, 0, out, outOff+16, 16);
	}
	
	public void decrypt(byte[] in, int inOff, byte[] out, int outOff) {
		byte[] L = new byte[16];
		byte[] R = new byte[16];
		byte[] temp = new byte[16];
		
		System.arraycopy(in, inOff, L, 0, 16);
		System.arraycopy(in, inOff+16, R, 0, 16);
		
		for (int i=15; i>=0; i--) {
			System.arraycopy(R, 0, temp, 0, 16);
			System.arraycopy(L, 0, R, 0, 16);
			serpent.encryptRound(L, 0, L, 0, i);
			for (int j=0; j<16; j++) {
				L[j] ^= temp[j];
			}
			
			System.arraycopy(R, 0, temp, 0, 16);
			System.arraycopy(L, 0, R, 0, 16);
			rijndael.encryptRound(L, 0, L, 0, i);
			for (int j=0; j<16; j++) {
				L[j] ^= temp[j];
			}
		}
		
		System.arraycopy(L, 0, out, outOff, 16);
		System.arraycopy(R, 0, out, outOff+16, 16);
	}
	
	public void ECB() {
		if (isEncryption) {
			// padding to be multiples of 256 bit
			byte[] inputEncryption = Arrays.copyOf(input, input.length+(32-(input.length%32)));
			
			// encrypt using ECB
			int i=0;
			while (i<inputEncryption.length/32) {
				encrypt(inputEncryption, i*32, inputEncryption, i*32);
				i++;
			}

			// add length info to output
			byte[] length = (Integer.toString(input.length)+"#").getBytes(StandardCharsets.UTF_8);
			output = Arrays.copyOf(length, length.length+inputEncryption.length);
			System.arraycopy(inputEncryption, 0, output, length.length, inputEncryption.length);
		}
		else {
			// get length info
			String inputString = new String(input, StandardCharsets.UTF_8);
			int firstFound = inputString.indexOf('#');
			int length = Integer.parseInt(inputString.substring(0, firstFound));
			byte[] inputDecryption = Arrays.copyOfRange(input, firstFound+1, input.length);
			
			// decrypt using ECB
			int i=0;
			while (i<inputDecryption.length/32) {
				decrypt(inputDecryption, i*32, inputDecryption, i*32);
				i++;
			}
			
			// remove padding
			output = Arrays.copyOf(inputDecryption, length);
		}
	}
	
	public void CBC() {
		if (isEncryption) {
			// padding to be multiples of 256 bit
			byte[] inputEncryption = Arrays.copyOf(input, input.length+(32-(input.length%32)));
			
			// TODO encrypt using CBC
			

			// add length info to output
			byte[] length = (Integer.toString(input.length)+"#").getBytes(StandardCharsets.UTF_8);
			output = Arrays.copyOf(length, length.length+inputEncryption.length);
			System.arraycopy(inputEncryption, 0, output, length.length, inputEncryption.length);
		}
		else {
			// get length info
			String inputString = new String(input, StandardCharsets.UTF_8);
			int firstFound = inputString.indexOf('#');
			int length = Integer.parseInt(inputString.substring(0, firstFound));
			byte[] inputDecryption = Arrays.copyOfRange(input, firstFound+1, input.length);
			
			// TODO decrypt using CBC
			
			
			// remove padding
			output = Arrays.copyOf(inputDecryption, length);
		}
	}
	
	public void CFB() {
		if (isEncryption) {
			// padding to be multiples of 256 bit
			byte[] inputEncryption = Arrays.copyOf(input, input.length+(32-(input.length%32)));
			
			// TODO encrypt using CFB
			

			// add length info to output
			byte[] length = (Integer.toString(input.length)+"#").getBytes(StandardCharsets.UTF_8);
			output = Arrays.copyOf(length, length.length+inputEncryption.length);
			System.arraycopy(inputEncryption, 0, output, length.length, inputEncryption.length);
		}
		else {
			// get length info
			String inputString = new String(input, StandardCharsets.UTF_8);
			int firstFound = inputString.indexOf('#');
			int length = Integer.parseInt(inputString.substring(0, firstFound));
			byte[] inputDecryption = Arrays.copyOfRange(input, firstFound+1, input.length);
			
			// TODO decrypt using ECB
			
			
			// remove padding
			output = Arrays.copyOf(inputDecryption, length);
		}
	}
	
	public void readInput() {
		if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			File file = fileChooser.getSelectedFile();
			try {
				input = Files.readAllBytes(file.toPath());
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
