package aes;
import java.util.*;

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
        {"08","2e","a1","66","28","9d","24","b2","76","5b","a2","49","6d","8b","d1","25"},
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
    public static String[] Xor(String arr1[], String arr2[]) {
        String result[] = new String[arr1.length];
        for(int i = 0; i < arr1.length; i++) {
            int x = Integer.parseInt(arr1[i],16);
            int y = Integer.parseInt(arr2[i],16);
            result[i] = Integer.toHexString(x ^ y);
        }
        return result;
    }
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
            result = result ^ Integer.parseInt("1b",16);
        }
        return result;
    }
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
    public static String[] encryption(String[] hextext,String[][] keys) {
        hextext = Xor(hextext,keys[0]);
        for(int i = 0; i < 10 ; i++) {
            hextext = subByte(hextext, false);
            hextext = shiftRow(hextext, false);
            if(i == 9) {
                hextext = Xor(hextext,keys[i+1]);
                continue;
            }
            hextext = mixColumn(hextext, false);
            hextext = Xor(hextext,keys[i+1]);
        }
        return hextext;
    }
    public static String[] decryption(String[] hexctext,String[][] keys) {
        hexctext = Xor(hexctext,keys[10]);
        hexctext = shiftRow(hexctext,true);
        hexctext = subByte(hexctext, true);
        for(int i = 1; i < 10 ; i++) {
            hexctext = Xor(hexctext,keys[10-i]);
            hexctext = mixColumn(hexctext, true);
            hexctext = shiftRow(hexctext,true);
            hexctext = subByte(hexctext, true);
        }
        hexctext = Xor(hexctext,keys[0]);
        return hexctext;
    }
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
    public static String[] merge(String[]... arrays) {
	List<String> list = new ArrayList<>();
	for (String[] array : arrays)
		Collections.addAll(list, array);
	return list.toArray(new String[0]);
    }
    public static void main(String[] args) {
        String text = "Two One Nine Two";
        String key = "Thats my Kung Fu";
        String hextext[] = new String[16];
        String hexkey[] = new String[16];
        String hexctext[] = new String[16];
        String invtext[] = new String[16];
        String roundkeys[][] = new String[11][16]; 
        String ctext = "", ptext = "";
        for(int i = 0; i < key.toCharArray().length; i++)
        {
            hextext[i] = Integer.toHexString(text.toCharArray()[i]);
            hexkey[i] = Integer.toHexString(key.toCharArray()[i]);
        }
        roundkeys[0] = hexkey;
        for(int i = 0; i < 10; i++) {
            hexkey = roundKey(hexkey, i);
            roundkeys[i+1] = hexkey;
        }
        hexctext = encryption(hextext,roundkeys);
        
        for(int i = 0; i < hexctext.length; i++){
            char temp = (char) Integer.parseInt(hexctext[i],16);
            ctext = ctext + temp;
        }
        System.out.println("Hexadecimal Result of AES 128-bit Encryption::  " + Arrays.toString(hexctext));
        System.out.println("String Result of AES 128-bit Encryption::  " + ctext);
        
        invtext = decryption(hexctext,roundkeys);
        for(int i = 0; i < invtext.length; i++) {
            char temp = (char) Integer.parseInt(invtext[i],16);
            ptext = ptext + temp;
        }
        System.out.println("Hexadecimal Result of AES 128-bit Decryption::  " + Arrays.toString(invtext));
        System.out.println("String Result of AES 128-bit Decryption::  " + ptext);
    }
}
