import java.util.Scanner;
import java.security.SecureRandom;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.MessageDigest;

class Generator {
	// Generates 32-bit (4 byte) random salt
	private static String generateSalt() {
		SecureRandom rand = new SecureRandom();
		byte bytes[] = new byte[2];
		rand.nextBytes(bytes);
		String salt = bytesToString(bytes);
		return salt;
	}

	// Byte to String Converter
	private static String bytesToString(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
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
	public static void main(String args[]) throws FileNotFoundException {

		//Ask for username
		Scanner scanner = new Scanner(System.in);
		System.out.print("Enter a username: ");
		String username = scanner.next();
		// Ask for password
		System.out.print("Enter a password: ");
		String password = scanner.next();
		scanner.close();
		System.out.println("Your username is " + username + " and your password is " + password);
		// Genertate a 32-bit salt
		String salt = generateSalt();
		System.out.println("Salt: " + salt);
		System.out.println("Password + salt " + password + salt);
		String hashThese = password + salt;
		// Generate hash
		String saltAndPass = getDigest(hashThese);
		System.out.println("Hashed password + salt: " + saltAndPass);
		// Store the username, salt, and salt + hash in pwd.txt
		PrintWriter outWriter = new PrintWriter("pwd.txt");
		outWriter.print("[" + username + "," + salt + "," + saltAndPass + "]");
		outWriter.close();
	}
}
