import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.io.*;

class Cracker {

	static int[] asciis = new int[69];
	static StringBuilder hash = new StringBuilder();
	static StringBuilder salt = new StringBuilder();
	static long trials = 0;

	public static void storeRelevantAsciis() {
		int i = 0;
		for (int asciiLowerCase = 97; asciiLowerCase <= 122; asciiLowerCase++) {
			asciis[i] = asciiLowerCase;
			i++;
		}
		for (int asciiUpperCase = 65; asciiUpperCase <= 90; asciiUpperCase++) {
			asciis[i] = asciiUpperCase;
			i++;
		}
		for (int asciiNumbers = 48; asciiNumbers <= 57; asciiNumbers++) {
			asciis[i] = asciiNumbers;
			i++;
		}
		for (int asciiMisc = 35; asciiMisc <= 42; asciiMisc++) {
			if (asciiMisc != 39) {
				asciis[i] = asciiMisc;
				i++;
			}
		}
	}

	// Hashing function
	private static String getDigest(String passAndSalt) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(passAndSalt.getBytes(StandardCharsets.UTF_8));
			String hashedPassword = bytesToString(hash);
			return hashedPassword;
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	// Byte to String Converter
	private static String bytesToString(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	// Check to see if hash matches original
	private static boolean isMatch(String pass) {
		String h = getDigest(pass + salt);
		if (h.equals(hash.toString())) {
			return true;
		}
		return false;
	}

	private static String calcPermutations(int[] asciis) {

		StringBuilder permutation = new StringBuilder();
		String s = "";
		int permutation_length = 0;
		for (int i = 0; i <= 68; i++) {
			if (permutation_length == 0) {
				permutation.append((char) asciis[i]);
				permutation_length++;
			} else {
				permutation.setCharAt(0, (char) asciis[i]);
			}

			for (int j = 0; j <= 68; j++) {
				if (permutation_length == 1) {
					permutation.append((char) asciis[j]);
					permutation_length++;
				} else {
					permutation.setCharAt(1, (char) asciis[j]);
				}
				s = permutation.substring(0,2);
				if(isMatch(s)) {return s;} else {trials++;}
				for (int k = 0; k <= 68; k++) {
					if (permutation_length == 2) {
						permutation.append((char) asciis[k]);
						permutation_length++;
					} else {
						permutation.setCharAt(2, (char) asciis[k]);
					}
					s = permutation.substring(0,3);
					if(isMatch(s)) {return s;} else {trials++;}
					for (int l = 0; l <= 68; l++) {
						if (permutation_length == 3) {
							permutation.append((char) asciis[l]);
							permutation_length++;
						} else {
							permutation.setCharAt(3, (char) asciis[l]);
						}
						s = permutation.substring(0,4);
						if(isMatch(s)) {return s;} else {trials++;}
						for (int z = 0; z <= 68; z++) {
							if (permutation_length == 4) {
								permutation.append((char)asciis[z]);
								permutation_length++;
							} else {
								permutation.setCharAt(4, (char) asciis[z]);
							}
							s = permutation.substring(0,5);
							if(isMatch(s)) {return s;} else {trials++;}
						}
					}
				}
			}
		}
		return "fail";
	}

	public static void main(String[] args) throws IOException {

		// Get hashed salt and password from file
		BufferedReader buffer = new BufferedReader(
				new InputStreamReader(new FileInputStream("pwd.txt"), Charset.forName("UTF-8")));
		int c = 0;
		int i = 0;
		while ((c = buffer.read()) != -1) {
			char character = (char) c;
			// System.out.print(character);
			if (character == ',') {
				i++;
			}
			if (i == 1 && character != ',') {
				// System.out.print(character);
				salt.append(character);
			}
			if (i == 2 && character != ',' && character != ']') {
				// System.out.print(character);
				hash.append(character);
			}
		}
		buffer.close();
		storeRelevantAsciis();
		double startTime = System.currentTimeMillis();
		String password = calcPermutations(asciis);
		double stopTime = System.currentTimeMillis();
		double elapsedTime = stopTime - startTime;
		System.out.println("Time needed to crack password: " + elapsedTime/1000 + " seconds");
		System.out.println("Trials: " + trials);
		System.out.println("salt: " + salt);
		System.out.println("hash: " + hash);
		System.out.println("password: " + password);
	}
}
