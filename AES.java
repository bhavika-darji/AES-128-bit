package aes;
import java.util.*;
// Create a class to AES 128-bit encryption
public class AES {
    static String sbox [][] = {
        {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
        {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
        {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
        {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
        {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
        {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
        {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
        {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
        {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
        {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
        {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
        {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
        {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
        {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
        {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
        {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"},
        };
    static String invsbox [][] = {
        {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
        {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
        {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
        {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
        {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
        {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
        {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
        {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
        {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
        {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
        {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
        {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
        {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
        {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
        {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
        {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"},
        };
    static String galois [][] = {
        {"02","03","01","01"},
        {"01","02","03","01"},
        {"01","01","02","03"},
        {"03","01","01","02"},
        };
     static String invgalois [][] = {
        {"14","11","13","09"},
        {"09","14","11","13"},
        {"13","09","14","11"},
        {"11","13","09","14"},
        };
    // convertArrayToMatrix() is use to convert single dimensional array to 4x4 dimensional array
    public static String[][] convertArrayToMatrix(String[] arr, boolean inv) {
        String w[][] = new String[4][4];
        int count = 0;
        for(int i = 0; i < 4; i++) { 
            for(int j = 0; j < 4; j++) {
                if(inv)
                    w[j][i] = arr[count];
                else
                    w[i][j] = arr[count];
                count++;
            }
        }
        return w;
    }
    // merge() method is used to merge two or more arrays into one
    public static String[] merge(String[]... arrays) {
	List<String> list = new ArrayList<>();
	for (String[] array : arrays)
		Collections.addAll(list, array);
	return list.toArray(new String[0]);
    }
    // Xor() method takes argument arrays and gives result by XORing them
    public static String[] Xor(String arr1[], String arr2[]) {
        String result[] = new String[arr1.length];
        for(int i = 0; i < arr1.length; i++) {
            int x = Integer.parseInt(arr1[i],16);
            int y = Integer.parseInt(arr2[i],16);
            //X-ORing the two values by ^ operator
            result[i] = Integer.toHexString(x ^ y);
        }
        return result;
    }
    // subByte() performs AES byte substitution from sbox and inverse sbox(invsbox) in encryption and decryption respectively
    public static String[] subByte(String arr[], boolean inv) {
        for(int i = 0; i < arr.length; i++) {
            if (arr[i].length() == 1)
                arr[i] = "0" + arr[i];
            char temp[] = arr[i].toCharArray();
            int x = Character.getNumericValue(temp[0]);
            int y = Character.getNumericValue(temp[1]); 
            if(inv)
                arr[i] = invsbox[x][y];
            else
                arr[i] = sbox[x][y];        
        }
        return arr;
    }
    // shiftRow() shifts row of array by their row_numer-1
    // eg: 1st row not get changed 2nd row shifts left by one in encryption and shifts right by one in decryption
    public static String[] shiftRow(String arr[], boolean inv) {
        String w[][] = convertArrayToMatrix(arr, true);
        int count = 0;
        for(int i = 0; i < 4; i++) {
            if(inv)
                Collections.rotate(Arrays.asList(w[i]), i);
            else    
                Collections.rotate(Arrays.asList(w[i]), -i);
        }
        for(int i = 0; i < 4; i++) { 
            for(int j = 0; j < 4; j++) {
                arr[count] = w[j][i];
                count++;
            }
        }
        return arr;
    }
    //mixColumns() multiples row of galois matrix and column of input data and then XORs them
    //The result multiplication and after XORing then became 1st value(0x0) of result matrix
    //Note: inverse galois(invgalois) matrix used in time of decryption
    public static String[] mixColumn(String arr[], boolean inv) { 
        int mulresult [] = new int[4];
        String w[][] = convertArrayToMatrix(arr, false);
        int count = 0, sum = 0;
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                for(int k =0; k < 4; k++) {
                    int t = Integer.parseInt(w[i][k],16);
                    int t2 = t;
                    if(inv) {
                        //to get result of multiplication in 8bit digit we have to use rule
                        //Rule established in the multiplication of the values as written in the book "Cryptography and Network Security"
                        if(invgalois[j][k] == "09") {
                            t = multiTwo(t);
                            t = multiTwo(t);
                            t = multiTwo(t);
                            t = t ^ t2;
                        }  
                        else if (invgalois[j][k] == "11") {
                            t = multiTwo(t);
                            t = multiTwo(t);
                            t = t ^ t2;
                            t = multiTwo(t);
                            t = t ^ t2;
                        }
                        else if (invgalois[j][k] == "13") {
                            t = multiTwo(t);
                            t = t ^ t2;
                            t = multiTwo(t);
                            t = multiTwo(t);
                            t = t ^ t2;
                        }
                        else if(invgalois[j][k] == "14")  {
                            t = multiTwo(t);
                            t = t ^ t2;
                            t = multiTwo(t);
                            t = t ^ t2;
                            t = multiTwo(t);
                        }
                    }
                    else {
                        if(galois[j][k] == "01") {        
                            t = t;
                        }
                        else if(galois[j][k] == "02"){
                            t = multiTwo(t);
                        }
                        else if(galois[j][k] == "03") {        
                            t = multiTwo(t);
                            t = t ^ t2;
                        }
                    }
                    mulresult[k] = t;  
                    sum = sum ^ mulresult[k];
                }
                arr[count] = Integer.toHexString(sum);
                sum = 0;
                count++;
            }
        }
        return arr;
    }
    // multiTwo() performs multiplication with 2 
    /* When any number(binary) multiplies with 2 in binary it can be implemented as a 
    1-bit left shift followed by a conditional bitwise XOR with 0001 1011 (1b in Hex)
    if the leftmost bit of the original value (before the shift) is 1 */ 
    public static int multiTwo(int num) {
        int result;
        String binary = Integer.toBinaryString(num);
        if(binary.length() != 8)
        for(int p = 0; p < 8 - binary.length(); p++)
            binary = "0" + binary;
        int flag = Character.compare(binary.charAt(0),'1');
        binary = binary.substring(1) + "0";
        result = Integer.parseInt(binary,2);
        if(flag == 0){
            result = result ^ Integer.parseInt("00011011", 2);
        }
        return result;
    }
    //roundKey() generates round keys for all 10 rounds 
    public static String[] roundKey(String key[], int roundnum) {
        String roundconst[] = new String[] {"01","02","04","08","10","20","40","80","1b","36"}; 
        String w[][] = convertArrayToMatrix(key, false);
        String w1[] = Arrays.copyOfRange(key, 12,16);
        Collections.rotate(Arrays.asList(w[3]), -1);
        w[3] = subByte(w[3], false);
        w[3][0] = Integer.toHexString(Integer.parseInt(w[3][0],16) ^ Integer.parseInt(roundconst[roundnum],16));
        w[0] = Xor(w[0],w[3]);
        w[1] = Xor(w[1],w[0]);
        w[2] = Xor(w[2],w[1]);
        w[3] = Xor(w[2],w1);
        key = merge(w[0],w[1],w[2],w[3]);
        return key;
    }
    // encryption() performs AES 128-bit Encryption with 16-bit input and 16-bit key 
    // Gives result of 16-bit encrypted data - Cipher Text
    public static String[] encryption(String[] hextext,String[][] keys) {
        // Before Starting round initially we have to add roundkey 0 to input data 
        hextext = Xor(hextext,keys[0]);
        // In AES 128-bit there are total 10 round of encryption 
        // Is executed by performing 4 steps: subByte, shiftRow, mixColumn and addRoundKey
        for(int i = 0; i < 10 ; i++) {
            hextext = subByte(hextext, false);
            hextext = shiftRow(hextext, false);
            // In last round there is no mixColumn only 3 step: subByte, shiftRow and addRoundKey
            if(i == 9) {
                hextext = Xor(hextext,keys[i+1]);
                continue;
            }
            hextext = mixColumn(hextext, false);
            // addRoundKey is XOR of data and generated key of that round
            hextext = Xor(hextext,keys[i+1]);
        }
        return hextext;
    }
    // Decryption() is inverse of encryption
    public static String[] decryption(String[] hexctext,String[][] keys) {
        // In round 1 of decryption there is no mixColumn only 3 step: subByte, shiftRow and addRoundKey
         // In decryption addRoundkey is performed by using keys in decreasing order
        // In 1st round of decryption we will use roundkey 10
        hexctext = Xor(hexctext,keys[10]);
        hexctext = shiftRow(hexctext,true);
        hexctext = subByte(hexctext, true);
        // Remaining rounds 2 - 10 is executed by performing 4 steps: subByte, shiftRow, mixColumn and addRoundKey
        for(int i = 1; i < 10 ; i++) {
            hexctext = Xor(hexctext,keys[10-i]);
            hexctext = mixColumn(hexctext, true);
            hexctext = shiftRow(hexctext,true);
            hexctext = subByte(hexctext, true);
        }
        // After Completing 10 rounds we have to add roundkey 0 to data 
        hexctext = Xor(hexctext,keys[0]);
        return hexctext;
    }
    public static void main(String[] args) {
        // Take input string and valid 16-bit key to encrypt from user
        Scanner sc= new Scanner(System.in);      
        System.out.print("Enter a string to Encrypt:: ");  
        String text = sc.nextLine();    
        System.out.print("Enter a 16-Bit Key for Encrypt:: ");  
        String key = sc.nextLine(); 
        while (key.length()!=16){
            System.out.print("Enter a valid Key 16-Bit only: ");
            key = sc.nextLine();
        }
        // If input string length is greater than 16 then we have to split it to as required as many 16-bits block 
        // eg: if total size is 40 then we will divide string into 3 16-bit block where in last block remaining size will occupied by " "(space)
        int size = text.length();
        if(size > 16)
            size = ((16 - (size % 16)) + text.length()) / 16;
        else 
            size = 1;
        int j = 0;
        // This variable contains array where each string is exact 16-bit length
        String textd[] = new String[size];
        // Assigning divided string to array variable
        if(text.length() > 16){
            for(int i = 0; i < size; i++){
                if(i == size-1)
                {
                    textd[i] = text.substring(j);
                    int temp = textd[i].length();
                    while(temp <= 16) {
                        textd[i] = textd[i].concat(" ");
                        temp++;
                    }
                    break;
                }
                textd[i] = text.substring(j,j+16);
                j= j+16;
            }
        }
        else {
            textd[0] = text.substring(j);
            int temp = textd[0].length();
            while(temp <= 16) {
                textd[0] = textd[0].concat(" ");
                temp++;
            }
        }
        System.out.println("16-bit blocks of given string:: " + Arrays.toString(textd));
        // These arrays are used to store hexadeimal value of string which will use to calculate cipher text
        String hextext[][] = new String[size][16];
        String hexctext[][] = new String[size][16];
        String invtext[][] = new String[size][16];
        String roundkeys[][] = new String[11][16];
        String hexkey[] = new String[16];
        String ctext = "", ptext = "";
        int flag = 0;
        // Converting String key of 16-bit to Hexadeciaml array 
        for(int i = 0; i < key.toCharArray().length; i++){
            hexkey[i] = Integer.toHexString(key.toCharArray()[i]);
        }
        // Generating keys for all rounds 1 to 10 (roundKeys)
        roundkeys[0] = hexkey;
        for(int i = 0; i < 10; i++) {
            hexkey = roundKey(hexkey, i);
            roundkeys[i+1] = hexkey;
        }
        // Performing Encryption and Decryption
        // Asking User if they want to perform Decryption or not
        System.out.print("Do You Want to Decrypt Text (Yes/No):: ");   
        String dec = sc.nextLine(); 
        while (dec.isEmpty()){
            System.out.print("Please Enter a valid value: Do You Want to Decrypt Text (Yes/No)::");
            dec = sc.nextLine();
        }
        if(dec.equalsIgnoreCase("Yes") || dec.equalsIgnoreCase("Y")) {
            //Set flag to one if they want
            flag = 1;
        }
        else if(dec.equalsIgnoreCase("No") || dec.equalsIgnoreCase("N")) { }
        else{
            System.out.print("Please Enter a valid value: ");
            dec = sc.next();
        }
        for(int k = 0; k < size; k++){
            for(int i = 0; i < 16; i++){
                hextext[k][i] = Integer.toHexString(textd[k].toCharArray()[i]);
            }
            hexctext[k] = encryption(hextext[k],roundkeys);
            if(flag == 1){
                invtext[k] = decryption(hexctext[k],roundkeys);
            }
        }
        // Converting Hexadecimal results of Encryption and Decryption to String 
        for(int k = 0; k < size; k++){
            for(int i = 0; i < hexctext[k].length; i++){
                char temp = (char) Integer.parseInt(hexctext[k][i],16);
                ctext = ctext + temp;
            }
            if(flag == 1) {
                for(int i = 0; i < invtext[k].length; i++) {
                    char temp = (char) Integer.parseInt(invtext[k][i],16);
                    ptext = ptext + temp;
                }
            }
        }
        // Printing the Results of Encryption and Decryption
        System.out.println("Hexadecimal Result of AES 128-bit Encryption::  " + Arrays.deepToString(hexctext));
        System.out.println("String Result of AES 128-bit Encryption::  " + ctext);
        if(flag == 1) {
            System.out.println("Hexadecimal Result of AES 128-bit Decryption::  " + Arrays.deepToString(invtext));
            System.out.println("String Result of AES 128-bit Decryption::  " + ptext);
        }
    }
}
