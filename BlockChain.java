package BlockChainMiniProjectsH;

//Libraries
import java.util.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.org.apache.bcel.internal.classfile.Signature;


//Public Key Container. 
class PublicKey {
    private int processID;
    private Key publicKey;

    PublicKey(int processID, Key publicKey) {
        this.processID = processID;
        this.publicKey = publicKey;}

    public Key getPublicKey() {
        return this.publicKey;}

    public int getPID() {
        return this.processID;}

    public void printInfo() {
        System.out.println("The process ID:\t" + processID + ", The Public Key:\t" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");}
}


class BlockRecord{
	  String transactions; //transactions of block
	  String blockHash; //hashcode of the record
	  String VerificationProcessID; //id of the processs
	  String previousBlockHash;	 //previous block hash thats used to link
	  String timeStamp; //timestamp of the record
	  
	  //Constructors use to instantiate BlockRecord variables
	  public String getVerificationProcessID() {return VerificationProcessID;}
	  public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
	  
	  public String getTransactions() {return transactions;}
	  public void setTransactions(String BID){this.transactions = BID;}
	  
	  public String getBlockHash() {return blockHash;}
	  public void setBlockHash(String BID){this.blockHash = BID;}

	  public String getTimeStamp() {return timeStamp;}
	  public void setTimeStamp(String TS){this.timeStamp = TS;}
 
	  public String getPreviousBlockHash() {return this.previousBlockHash;}
	  public void setPreviousBlockHash (String PH){this.previousBlockHash = PH;}
	}

class Block {
	private String [] transactions; //list of transactions
	private int blockHash; 			//value of the block
	private int previousBlockHash; 	//has of the previous block
	private Timestamp timeStamp; 	//has of the previous block
	
	public Block(String[] transactions, int previousBlockHash, Timestamp timeStamp) { //constructor
		super();
		this.transactions = transactions; 
		this.previousBlockHash = previousBlockHash;
		this.timeStamp = timeStamp;
		this.blockHash = Arrays.hashCode(new int[] {Arrays.hashCode(transactions), this.previousBlockHash});
		//calculated field based on hash of current transactions and previous block hash
		
	}
	@Override
	public String toString() {
		return "Block [transactions=" + Arrays.toString(transactions) + ", blockHash=" + blockHash
				+ ", previousBlockHash=" + previousBlockHash + ", timeStamp=" + timeStamp + "]";
	}
	public String[] getTransactions() {
		return transactions;
	}
	public void setTransactions(String[] transactions) {
		this.transactions = transactions;
	}
	public int getBlockHash() {
		return blockHash;
	}
	public void setBlockHash(int blockHash) {
		this.blockHash = blockHash;
	}
	public int getPreviousBlockHash() {
		return previousBlockHash;
	}
	public void setPreviousBlockHash(int previousBlockHash) {
		this.previousBlockHash = previousBlockHash;
	}
	public Timestamp getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(Timestamp timeStamp) {
		 this.timeStamp = timeStamp;
	}}


//From Dr. Elliot's utility code
class KeyPairUtility {	
    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
    }}
	

//Container class that contains the ports for the Key, unverified block and blockchain iteself.
class Ports {
    final static int KeyServerStart = 4710;
    final static int UnverifiedBlockServerPortStart = 4820;
    final static int BlockchainServerPortStart = 4930;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    //constructor for the ports
    public void setPorts(){
        KeyServerPort = KeyServerStart + BlockChain.PID;
        UnverifiedBlockServerPort = UnverifiedBlockServerPortStart + BlockChain.PID;
        BlockchainServerPort = BlockchainServerPortStart + BlockChain.PID;
    }
}


//This is supposed to be the worker for the public key... not working.
class PublicKeyWorker extends Thread {
    Socket socket;
    PublicKeyWorker(Socket socket) {
    this.socket = socket;
    }
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            int processID = Integer.parseInt(in.readLine());
            String key = in.readLine();
            byte[] keyBytes = Base64.getDecoder().decode(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            try {
            	BlockChain.publicKeys[processID] = new PublicKey(processID, KeyFactory.getInstance("RSA").generatePublic(keySpec));
            } catch (Exception exc) {
                exc.printStackTrace();
            }
            System.out.println("processID " + processID + " key " + key + "\n");
            socket.close();
        } catch (IOException x) {
            x.printStackTrace();
        }
    }}

//This is supposed to be the server for the public key... not used.
class PublicKeyServer implements Runnable {

    public void run() {
        int q_len = 6;
        Socket socket;
        System.out.println("Public Keys " + Integer.toString(Ports.KeyServerPort));
        System.out.println("Looking for this key\n");
        try {
            ServerSocket serverSocket = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                socket = serverSocket.accept();
                new PublicKeyWorker(socket).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }}}




    
public class BlockChain{
	
	static String serverName = "localhost";
    static String file;
    static int PID = 0;
    static int numProcesses = 3;
    static KeyPair KeyPair;
    static PublicKey[] publicKeys = new PublicKey[3];
    static BlockingQueue<BlockRecord> unverifiedBlockQueue = new PriorityBlockingQueue<>();
    static String theBlockchain;        
    
    
    //This should be a fully functioning multicast function, not quite all the way implemented... should be able 
    //to chose which to multicast... the key, the individual block, or the entire chain.
    public static void multiCasting(boolean Key, boolean Block, boolean Chain) {
        Socket socket;
        PrintStream toServer;

        if (Key) { //multicast key
            try {
                for (int i = 0; i < numProcesses; i++) {
                    socket = new Socket(serverName, Ports.KeyServerStart + i);
                    toServer = new PrintStream(socket.getOutputStream());
                    toServer.println(PID);
                    toServer.println(Base64.getEncoder().encodeToString(KeyPair.getPublic().getEncoded()));
                    toServer.flush();
                    socket.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            if (Block) { //multicast block
                try {
                    for (int i = 0; i < numProcesses; i++) {
                        socket = new Socket(serverName, Ports.BlockchainServerPortStart + i);
                        toServer = new PrintStream(socket.getOutputStream());
                        toServer.println(BlockChain.PID);
                        toServer.println(theBlockchain);
                        toServer.flush();
                        socket.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }//should multicast chain
        }}}     

	
    //This function translates the block into JSON format for multicasting...
    //It takes the ID, transaction, hash and timestamp as inputs...
	public static void WriteJSON(String VerificationProcessID, String Transactions, String BlockHash, String TimeStamp,
			String PreviousBlockHash){
	    System.out.println("=========> In WriteJSON <=========\n");
	    UUID BinaryUUID = UUID.randomUUID();
	    String suuid = BinaryUUID.toString();
	    System.out.println("Unique Block ID: " + suuid + "\n");
	    
	    BlockRecord blockRecord = new BlockRecord();
	    blockRecord.setVerificationProcessID(VerificationProcessID);
	    blockRecord.setTransactions(Transactions);
	    blockRecord.setBlockHash(BlockHash);
	    blockRecord.setTimeStamp(TimeStamp); 
	    blockRecord.setPreviousBlockHash(PreviousBlockHash);
	    
	    String catRecord = // Hash a string...   
	      blockRecord.getVerificationProcessID() +
	      blockRecord.getTransactions() +
	      blockRecord.getBlockHash() +
	      blockRecord.getTimeStamp() +
	      blockRecord.getPreviousBlockHash();
	    
	    System.out.println("String blockRecord is: " + catRecord);

	    /* Now make the SHA-256 Hash Digest of the block: */
	    
	    String SHA256String = "";

	    try{
	      MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
	      ourMD.update (catRecord.getBytes());
	      byte byteData[] = ourMD.digest();

	      StringBuffer sb = new StringBuffer();
	      for (int i = 0; i < byteData.length; i++) {
		sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
	      }
	      SHA256String = sb.toString(); 
	    }catch(NoSuchAlgorithmException x){};
	    
	    
	    /* This shows what the JSON will look like*/

	    Gson gson = new GsonBuilder().setPrettyPrinting().create();

	    // Convert the Java object to a JSON String:
	    String json = gson.toJson(blockRecord);
	    
	    System.out.println("\nJSON String blockRecord is: " + json);

	    // Write the JSON object to a file:
	    try (FileWriter writer = new FileWriter("blockRecord.json")) {
	      gson.toJson(blockRecord, writer);
	    } catch (IOException e) {
	      e.printStackTrace();
	    }
	  }
	
	
	//This function reads in the the JSON to a java object for multicasting...
	 public static void ReadJSON(){
		    System.out.println("\n=========> In ReadJSON <=========\n");		    
		    Gson gson = new Gson();
		    try (Reader reader = new FileReader("blockRecord.json")) {		      
		      // Read and convert JSON File to a Java Object:
		      BlockRecord blockRecordIn = gson.fromJson(reader, BlockRecord.class);		      
		      // Print the blockRecord:
		      System.out.println(blockRecordIn);
		      System.out.println("Name is: " + blockRecordIn.transactions);
		    } catch (IOException e) {
		      e.printStackTrace();
		    }
		  }
	
		
	public static void main(String a[]) throws Exception { 
		
	//Hash function, that should be used to verify work... ideally...
	String statement1 = "sample string";
	int hashValue = statement1.hashCode(); // this hashValue int is constructed from the string above	 
	System.out.println("hashValue = "+ hashValue);	
	ArrayList<Block> blockChain = new ArrayList<Block>(); //creates a new array of blocks
	
	//Give the blockchain a Process ID
	int PID;
	// This should be for a command line, idealy
    PID = (a.length < 1) ? 0 : Integer.parseInt(a[0]);
    System.out.print("process is "+PID +"\n"); 
	
	//BlockOne
	Timestamp timeStamp = new Timestamp(System.currentTimeMillis()); 	// creates a time stamp for the block
	String [] initialValues = {"100 to paul", "200 to dave"};  			//gives the block chain two values for the transactions
	Block firstBlock = new Block(initialValues, 0, timeStamp); 			//makes a new block of the transactions and the 
	blockChain.add(firstBlock);
	System.out.println("First block is " +firstBlock.toString());
	System.out.println("The block chain is " +blockChain.toString() +"\n");
	
	System.out.println("LOOK"+firstBlock.getBlockHash());
	 
	 WriteJSON(String.valueOf(PID), Arrays.toString(firstBlock.getTransactions()), String.valueOf(firstBlock.getBlockHash()), String.valueOf(firstBlock.getTimeStamp()), 
			 String.valueOf(firstBlock.getPreviousBlockHash()));
	ReadJSON();
	
	//BlockTWo
	Timestamp timeStampSecond = new Timestamp(System.currentTimeMillis());
	String [] secondValues = {"100 back from paul", "200 back from dave"};
	Block secondBlock = new Block(secondValues, firstBlock.getBlockHash(), timeStampSecond);
	blockChain.add(secondBlock);
	System.out.println("Second block is " +secondBlock.toString());
	System.out.println("The block chain is " +blockChain.toString() +"\n");
	
	WriteJSON(String.valueOf(PID), Arrays.toString(secondBlock.getTransactions()), String.valueOf(secondBlock.getBlockHash()), String.valueOf(secondBlock.getTimeStamp()), 
	String.valueOf(secondBlock.getPreviousBlockHash()));
	ReadJSON();
	
	//BlockThree
	Timestamp timeStampThird = new Timestamp(System.currentTimeMillis());
	String [] thirdValues = {"100 to Mary", "200 to sarah"};
	Block thirdBlock = new Block(thirdValues, secondBlock.getBlockHash(), timeStampThird);
	blockChain.add(thirdBlock);
	System.out.println("Third block is " +thirdBlock.toString());
	System.out.println("The block chain is " +blockChain.toString() +"\n");
	
	WriteJSON(String.valueOf(PID), Arrays.toString(thirdBlock.getTransactions()), String.valueOf(thirdBlock.getBlockHash()), String.valueOf(thirdBlock.getTimeStamp()), 
	String.valueOf(thirdBlock.getPreviousBlockHash()));	
	ReadJSON();
	
	//BlockFour
	Timestamp timeStampFourth = new Timestamp(System.currentTimeMillis());
	String [] fourthValues = {"Tim gives shad 10", "Terry gives 50 to shad"};
	Block fourthBlock = new Block(fourthValues, thirdBlock.getBlockHash(), timeStampFourth);
	blockChain.add(fourthBlock);
	System.out.println("Fourth block is " +fourthBlock.toString());
	System.out.println("The block chain is " +blockChain.toString() +"\n");
	
	WriteJSON("Process1", Arrays.toString(fourthBlock.getTransactions()), String.valueOf(fourthBlock.getBlockHash()), String.valueOf(fourthBlock.getTimeStamp()), 
	String.valueOf(fourthBlock.getPreviousBlockHash()));	
	ReadJSON();
	
	//Used to generate the public and private key	
    try {
        KeyPair = KeyPairUtility.generateKeyPair(System.currentTimeMillis() * PID);
        publicKeys[PID] = new PublicKey(PID, KeyPair.getPublic());
    } catch (Exception e) {}

    new Ports().setPorts();
    new Thread(new PublicKeyServer()).start();
    //multiCasting(true, false, false); 
	
	}}

