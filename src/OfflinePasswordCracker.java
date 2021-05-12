//Offline Password Cracker
//Matthew Lewis
//CI510 Security and Dependability
//2021

import java.io.File;
import java.util.Scanner;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;

public class OfflinePasswordCracker {
	
	public static void main(String[] args) {
		//Creates the Scanner object for retrieving user input
		Scanner userScan = new Scanner(System.in);
		System.out.println("*****************************************************************************");
		System.out.println("Please select an attack method by entering the corresponding number as below.");
		System.out.println("*****************************************************************************");
		System.out.println("\n1 - Dictionary\n2 - Brute Force");
		System.out.println("\n\nType here: ");
		Integer attackMethod = userScan.nextInt();
		
		switch (attackMethod) {
			case 1:
				//Dictionary Attack
				System.out.println("Dictionary Attack\n");
				
				//Takes the location of the dictionary from the user
				System.out.println("Please enter the filename of the dictionary file:");
				String dictPath = userScan.next();
				ArrayList<String> dictArrayList = new ArrayList<String>();
				loadFile(dictPath, dictArrayList);
				
				//Finds and loads the password file
				System.out.println("Please enter the filename of the hashed passwords file:");
				String hashPath1 = userScan.next();
				ArrayList<String> hashArrayList1 = new ArrayList<String>();
				loadFile(hashPath1, hashArrayList1);
				

				//Records time that attack begins
				long attackStartTime = System.nanoTime();
				
				System.out.println("\nPerforming Dictionary attack.\n");
				int noResults = 0;
				//Hashes each word in the dictionary and compares it to the hashes in the password file
				for (int i = 0; i < dictArrayList.size(); i++) {
					String wordHash = MD5Hash(dictArrayList.get(i));
					if (hashArrayList1.contains(wordHash)) {
						System.out.println(dictArrayList.get(i) + " hashed is " + MD5Hash(dictArrayList.get(i)));
						noResults ++;
					}
				}
				//Informs the user that the attack is complete and how many passwords were found
				System.out.println("\nDictionary attack complete.");
				
				//Records Finishing time and finds how long Dict attack took
				long attackFinishTime = System.nanoTime();
				long attackTimeNano = attackFinishTime - attackStartTime;
				double attackTimeSecs = (double) attackTimeNano / 1000000000;
				
				System.out.println("\n" + noResults + " matching hashes found out of " + hashArrayList1.size() + ".");
				System.out.println("\nDictionary Attack took: " + attackTimeSecs + " seconds to complete.");
				
				break;
				
			case 2:
				//Brute Force Attack
				System.out.println("Brute Force Attack\n");
				
				//Finds and loads the password file
				System.out.println("Please enter the filename of the hashed passwords file:");
				String hashPath2 = userScan.next();
				ArrayList<String> hashArrayList2 = new ArrayList<String>();
				loadFile(hashPath2, hashArrayList2);
				
				//Sets the maximum string size to check
				System.out.println("Please enter the maximum number of characters in a password.");
				int maxLength = userScan.nextInt();
				
				bruteForce(maxLength, hashArrayList2);
				
				break;
				
			default:
				//When an invalid attack number has been entered
				System.out.println("Invalid attack method");
				break;
		}
		//Terminates the Scanner object
		userScan.close();;
		
	}
	
	public static void loadFile(String in, ArrayList<String> myList) {
		//Attempts to open and read the provided dictionary file
		try {
			//Creates a File object to contain the .txt and a Scanner object to read it
			File wordFile = new File(in);
			Scanner myScanner = new Scanner(wordFile);
			//Adds each line (word) to the ArrayList
			while (myScanner.hasNextLine()) {
				String word = myScanner.nextLine();
				myList.add(word);
			}
			myScanner.close();
		}
		//If the file entered cannot be opened, handles the exception
		catch (FileNotFoundException e) {
			System.out.println("File could not be found.");
		}
	}
	
	public static String MD5Hash(String in) {
		String hashed = "";
		try {
			//Creates new MessageDigest MD5 instance
			MessageDigest md = MessageDigest.getInstance("MD5");
			//Takes the input
			byte[] messageDigest = md.digest(in.getBytes());
			//Converts byte array into sign magnitude form
			BigInteger num = new BigInteger(1, messageDigest);
			//Covert BigIntger into a string
			hashed = num.toString(16);
			while (hashed.length() < 32) {
				hashed = "0" + hashed;
			}
		}
		catch (NoSuchAlgorithmException e) {
			System.out.println("Defined algorithm could not be found.");
		}
		
		return hashed;
	}
	
	public static void bruteForce(int maxLength, ArrayList<String> myList) {
		

		//Records time that attack begins
		long bruteStartTime = System.nanoTime();
		
		//Defines the number of characters and uses that to work out the number of permutations possible
		int characters = 26;
		int noPermu = (int) Math.pow(characters, maxLength);
		String plainText;
		String hash;
		StringBuilder sb = new StringBuilder(maxLength);
		ArrayList<String> foundWords = new ArrayList<String>();
		
		System.out.println("\nPerforming Brute Force attack.\n");
		
		//A loop that will generate each permutation, hash it and compare it to the hashes provided
		for (int i = 0; i < noPermu; i++) {
		    sb.setLength(0);
		    //For each character in the string builder, cycles it through the available characters
		    for (int j = 0, k = i; j < maxLength; j++, k /= characters) { 
		        sb.insert(0, (char) ('a' + k % characters));
		    	plainText = sb.toString();
		    	hash = MD5Hash(plainText);
		    	
		    	//Checks that the generated hash is in the provided file and has not already been found
		    	if (myList.contains(hash) && !foundWords.contains(plainText)) {
		    		System.out.println(plainText + " hashed is " + hash);
		    		foundWords.add(plainText);
		    	}
			} 
		}
		System.out.println("\nBrute Force attack complete.");
		
		//Records Finishing time and finds how long Brute Force attack took
		long bruteFinishTime = System.nanoTime();
		long bruteTimeNano = bruteFinishTime - bruteStartTime;
		double bruteTimeSecs = (double) bruteTimeNano / 1000000000;
		
		System.out.println("\n" + foundWords.size() + " matching hashes found out of " + myList.size() + ".");
		System.out.println("Brute Force Attack took: " + bruteTimeSecs + " seconds to complete.");
		if (foundWords.size() < myList.size()) {
			System.out.println("To find remaining hashes, try allowing for more characters.");
		}
	}
}