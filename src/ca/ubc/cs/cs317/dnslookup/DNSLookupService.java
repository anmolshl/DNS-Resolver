package ca.ubc.cs.cs317.dnslookup;

import java.io.*;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    private static int offset;
    private static byte[] bytes;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        Set<ResourceRecord> cachedResults = cache.getCachedResults(node);
        if (!cachedResults.isEmpty()) {
            return cachedResults;
        }
        // optimization: check if this node has a CNAME result
        cachedResults = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));
        if (!cachedResults.isEmpty()) {
            return handleCachedCName(cachedResults, node, indirectionLevel);
        }

        DNSLookupService.retrieveResultsFromServer(node, rootServer);
        cachedResults = cache.getCachedResults(node);

        if (!cachedResults.isEmpty()) {
            Object[] records = cachedResults.toArray();
            ResourceRecord first = (ResourceRecord)records[0];
            if (first.getTTL() == -1) {
                // invalid response?
                return Collections.emptySet();
            }
        } else {
            // check for CNAME
            cachedResults = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));
            if (!cachedResults.isEmpty()) {
                return handleCachedCName(cachedResults, node, indirectionLevel);
            }
        }

        return cachedResults;
    }

    /**
     * Handles redirecting a query if it already has a cached CNAME result.
     * Immediately queries for the CNAME instead.
     *
     * @param cachedResults the cached results including the CNAME
     * @param node the original DNSNode asked for
     * @param indirectionLevel carried over from getResults to maintain cutoff at 10 CNAMEs
     */
    private static Set<ResourceRecord> handleCachedCName(Set<ResourceRecord> cachedResults, DNSNode node, int indirectionLevel) {
        Object[] records = cachedResults.toArray();
        ResourceRecord first = (ResourceRecord)records[0];
        if (first.getTTL() == -1) {
            return Collections.emptySet();
        }
        return getResults(new DNSNode(first.getTextResult(), node.getType()), ++indirectionLevel);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] query = generateQuery(node);
        DatagramPacket sendPacket = new DatagramPacket(query, query.length, server, DEFAULT_DNS_PORT);
        List<ResourceRecord> records = sendDatagram(sendPacket, 1, node);

        Set<ResourceRecord> cached = cache.getCachedResults(node);
        if (cached.isEmpty()) {
            ResourceRecord ns = null;
            for (ResourceRecord r : records) {
                if (r.getType() == RecordType.A) {
                    ns = r;
                    break;
                }
            }
            if (ns == null) {
                //weird edge case where the server doesn't give us the IP for the NS...
                ResourceRecord nameServer = null;
                for (ResourceRecord r : records) {
                    if (r.getType() == RecordType.NS) {
                        nameServer = r;
                    }
                }
                if (nameServer != null) {
                    DNSNode nsNode = new DNSNode(nameServer.getTextResult(), RecordType.A);
                    retrieveResultsFromServer(nsNode, rootServer);
                    Set<ResourceRecord> cachedNS = cache.getCachedResults(nsNode);
                    for (ResourceRecord r : cachedNS) {
                        if (r.getType() == RecordType.A) {
                            retrieveResultsFromServer(node, r.getInetResult());
                            break;
                        }
                    }
                }
            } else {
                if (ns.getInetResult() != null) {
                    retrieveResultsFromServer(node, ns.getInetResult());
                }
            }

        }
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    /**
     * Attempts to send the datagram containing the query to a DNS server.
     * Gives up after two failed attempts.
     *
     * @param node          Host name and record type used for the query.
     * @param sendCount     A counter for the number of attempts.
     * @param sendPacket    The datagram to send.
     * @return List<ResourceRecord> the resource records processed from the response
     */
    private static List<ResourceRecord> sendDatagram(DatagramPacket sendPacket, int sendCount , DNSNode node){
        try {
            byte[] queryId = Arrays.copyOfRange(sendPacket.getData(),0,2);
            int id = ((queryId[0] << 8) & 0xFFFF) | (queryId[1] & 0xFF);
            socket.send(sendPacket);
            if (verboseTracing) {
                System.out.println();
                System.out.println();
                System.out.println("Query ID     " + id + " " + node.getHostName() + "  " + node.getType() + " --> "
                        + sendPacket.getAddress().getHostAddress());
            }
            return receiveResponse(queryId);

        }catch(Exception e){
            if(sendCount > 2) {
                return new ArrayList<>();
            }
            else{
                return sendDatagram(sendPacket, sendCount + 1 , node);
            }
        }
    }

    /**
     * Creates a DNS query from the given DNSNode.
     *
     * @param node    Host name and record type used for the query.
     * @return byte[], the query to send
     */
    private static byte[] generateQuery(DNSNode node) {
        byte[] query = new byte[512];
        int index = 0;

        int transactionId = random.nextInt() % 0xFFFF;
        query[index++] = (byte)(transactionId >> 8);
        query[index++] = (byte)(transactionId);

        // standard query 0x0000
        query[index++] = 0;
        query[index++] = 0;

        // 1 question
        query[index++] = 0;
        query[index++] = 1;

        // 0 ans, auth, additional
        for (int i = 0; i < 6; i++) {
            query[index++] = 0;
        }

        // encode the domain name
        String name = node.getHostName();
        String[] parts = name.split("\\.");
        for (int j = 0; j < parts.length; j++) {
            String part = parts[j];
            query[index++] = (byte)part.length();
            byte[] encoded = part.getBytes();
            for (int k = 0; k < encoded.length; k++) {
                query[index++] = encoded[k];
            }
        }
        // end with a 0
        query[index++] = 0;

        // type
        query[index++] = 0;
        query[index++] = (byte)node.getType().getCode();

        // class IN
        query[index++] = 0;
        query[index++] = 1;

        // get the right length
        byte[] truncated = new byte[index];
        System.arraycopy(query,0, truncated, 0, index);
        return truncated;
    }

    /**
     * Sends a DNS query and receives the DNS response.
     *
     * @param id the two bytes containing the query ID
     * @return @return List<ResourceRecord> all records processed
     */
    private static List<ResourceRecord> receiveResponse(byte[] id) throws IOException {
        byte[] buf = new byte[1024];
        DatagramPacket rec = new DatagramPacket(buf, buf.length);
        socket.receive(rec);
        byte[] response = rec.getData();
        if (rec.getLength() == 1024) {
            throw new IOException("Response size too large");
        }
        boolean isCorrectId = response[0] == id[0] && response[1] == id[1];
        if (!isCorrectId) {
            // we received the wrong packet, try again
            throw new IOException("Invalid query id");
        }
        return handleDNSResponse(Arrays.copyOfRange(response, 0, rec.getLength()));
    }

    /**
     * Parses the DNS Response into ResourceRecords.
     *
     * @param response the DNS response
     * @return List<ResourceRecord> all records processed
     */
    private static List<ResourceRecord> handleDNSResponse(byte[] response) throws IOException{
        List<ResourceRecord> records = new ArrayList<>();
        offset = 0;
        bytes = response;
        int tID = readShort(bytes) & 0xFFFF;
        int header = readShort(bytes);
        int rCd = header & 0xF;
        if (rCd == 3 || rCd == 5) {
            throw new IOException("Error code received from server");
        }
        boolean isAuth = (header & 0x0400) > 0;
        if (verboseTracing) {
            System.out.println("Response ID: " + tID + " Authoritative = " + isAuth);
        }

        int questionCount = readShort(bytes);
        int answerCount = readShort(bytes);
        int authCount = readShort(bytes);
        int arCount = readShort(bytes);

        for(int i = 0; i<questionCount; i++){
            // throw away the questions, we don't need it
            removeQueryFromResponse();
        }

        if (verboseTracing) {
            System.out.println("  Answers (" + answerCount + ")");
        }
        for(int i = 0; i<answerCount; i++){
            ResourceRecord record = parseResourceRecord();
            records.add(record);
            verbosePrintResourceRecord(record, record.getType().getCode());
        }

        if (verboseTracing) {
            System.out.println("  Nameservers (" + authCount + ")");
        }
        for(int i = 0; i<authCount; i++) {
            ResourceRecord record = parseResourceRecord();
            records.add(record);
            verbosePrintResourceRecord(record, record.getType().getCode());
        }

        if (verboseTracing) {
            System.out.println("  Additional Information (" + arCount + ")");
        }
        for(int i = 0; i<arCount; i++) {
            ResourceRecord record = parseResourceRecord();
            records.add(record);
            verbosePrintResourceRecord(record, record.getType().getCode());
        }

        for(ResourceRecord r : records) {
            cache.addResult(r);
        }
        return records;
    }

    private static void removeQueryFromResponse() {
        while(bytes[offset++] != 0) {}
        offset += 4;
    }

    /**
     * Reads a name from the DNS response. Handles message compression.
     *
     * @param off the initial offset to start reading data from
     * @return NameOffset, a tuple containing the name and the amount of bytes read
     */
    private static NameOffset parseName(int off) {
        int numChars = bytes[off++];

        if (numChars < 0) {
            //pointer
            int jumpTo = (short) (((numChars & 0x3F) << 8) | (bytes[off++] & 0xFF));
            String name = parseName(jumpTo).name;
            return new NameOffset(name, 2);
        }

        if (numChars == 0) {
            // end
            return new NameOffset("", 1);
        }

        String partialName = new String(Arrays.copyOfRange(bytes,off,off+numChars));
        NameOffset rest = parseName(off+numChars);
        String dot = (rest.name.equals("") ? "" : ".");
        return new NameOffset(partialName + dot + rest.name, rest.offset + 1 + numChars);
    }

    /**
     * Parses a ResourceRecord from the DNS response.
     * @return ResourceRecord
     */
    private static ResourceRecord parseResourceRecord() throws UnknownHostException {
        NameOffset no = parseName(offset);
        String name = no.name;
        offset += no.offset;
        RecordType type = RecordType.getByCode((int)readShort(bytes));
        short cls = readShort(bytes);
        long TTL = readTTL(bytes); // TODO unsigned?
        int dataLen = readShort(bytes);
        if (type == RecordType.A || type == RecordType.AAAA) {
            InetAddress addr = InetAddress.getByAddress(readBytes(dataLen, bytes));
            return new ResourceRecord(name, type, TTL, addr);
        } else {
            NameOffset result = parseName(offset);
            offset += dataLen;
            return new ResourceRecord(name, type, TTL, result.name);
        }
    }

    private static byte[] readBytes(int numBytes, byte[] bytes) {
        byte[] ba = new byte[numBytes];
        System.arraycopy(bytes, offset, ba, 0, numBytes);
        offset += numBytes;
        return ba;
    }

    private static short readShort(byte[] bytes) {
        byte hi = bytes[offset++];
        byte lo = bytes[offset++];
        return (short)((hi&0xFF)<<8 | (lo&0xFF));
    }

    private static long readTTL(byte[] bytes){
        byte b1 = bytes[offset++];
        byte b2 = bytes[offset++];
        byte b3 = bytes[offset++];
        byte b4 = bytes[offset++];
        return ((b1&0xFF)<<24 | (b2&0xFF)<<16 | (b3&0xFF)<<8 | (b4&0xFF));
    }
}
