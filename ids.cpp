/**
 * ============================================================================
 *   MINI-IDS - A Real Time Data Capturing Tool
 *   REAL-TIME NETWORK INTRUSION DETECTION SYSTEM
 * ============================================================================
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <ctime>
#include <thread>
#include <map>
#include <set>
#include <algorithm>
#include <conio.h>
#include <fstream>
#include <vector>

#ifdef _WIN32
    #define HAVE_REMOTE
    #include <pcap.h>
    #include <winsock2.h>
    #include <windows.h>
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "Packet.lib")
    #pragma comment(lib, "ws2_32.lib")
#endif

using namespace std;

#ifdef _WIN32
    HANDLE hConsole;
    void setColor(int color) {
        SetConsoleTextAttribute(hConsole, color);
    }
#else
    void setColor(int c) {
        if(c==10) cout << "\033[32m";
        else if(c==11) cout << "\033[36m";
        else if(c==12) cout << "\033[31m";
        else if(c==13) cout << "\033[35m";
        else if(c==14) cout << "\033[33m";
        else if(c==15) cout << "\033[37m";
        else cout << "\033[0m";
    }
#endif

// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct AttackLog {
    int id;
    string timestamp;
    string srcIP;
    string dstIP;
    int dstPort;
    string attackType;
    AttackLog* next;
    AttackLog() : id(0), dstPort(0), next(nullptr) {}
};

class LinkedList {
private:
    AttackLog* head;
    int count;
public:
    LinkedList() : head(nullptr), count(0) {}
    
    void add(AttackLog* node) {
        count++;
        if(!head) { head = node; return; }
        AttackLog* temp = head;
        while(temp->next) temp = temp->next;
        temp->next = node;
    }
    
    AttackLog* linearSearch(const string& ip) {
        AttackLog* temp = head;
        while(temp) {
            if(temp->srcIP == ip) return temp;
            temp = temp->next;
        }
        return nullptr;
    }
    
    AttackLog** toArray() {
        AttackLog** arr = new AttackLog*[count];
        AttackLog* temp = head;
        for(int i=0; i<count && temp; i++) {
            arr[i] = temp;
            temp = temp->next;
        }
        return arr;
    }
    
    void bubbleSortByTime() {
        if(count <= 1) return;
        AttackLog** arr = toArray();
        for(int i=0; i<count-1; i++)
            for(int j=0; j<count-i-1; j++)
                if(arr[j]->timestamp > arr[j+1]->timestamp)
                    swap(arr[j], arr[j+1]);
        head = arr[0];
        for(int i=0; i<count-1; i++) arr[i]->next = arr[i+1];
        arr[count-1]->next = nullptr;
        delete[] arr;
    }
    
    void selectionSortByPort() {
        if(count <= 1) return;
        AttackLog** arr = toArray();
        for(int i=0; i<count-1; i++) {
            int minIdx = i;
            for(int j=i+1; j<count; j++)
                if(arr[j]->dstPort < arr[minIdx]->dstPort) minIdx = j;
            if(minIdx != i) swap(arr[i], arr[minIdx]);
        }
        head = arr[0];
        for(int i=0; i<count-1; i++) arr[i]->next = arr[i+1];
        arr[count-1]->next = nullptr;
        delete[] arr;
    }
    
    void traverse(void (*callback)(AttackLog*)) {
        AttackLog* temp = head;
        while(temp) { callback(temp); temp = temp->next; }
    }
    
    int size() { return count; }
    
    ~LinkedList() {
        while(head) { AttackLog* t = head; head = head->next; delete t; }
    }
};

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

pcap_t* pcapHandle = nullptr;
int packetCounter = 0;
int totalPackets = 0;
int suspiciousCount = 0;
set<string> blockedIPs;
map<string, int> attackTracker;
LinkedList logList;
bool isCapturing = false;
vector<string> interfaceNames;

const string LOG_FILE = "ids_all_logs.txt";

// ============================================================================
// TIME FUNCTION
// ============================================================================

string getCurrentTimestamp() {
    time_t now = time(nullptr);
    string ts = ctime(&now);
    ts.pop_back();
    return ts;
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

void saveLogToFile(AttackLog* log) {
    ofstream file(LOG_FILE, ios::app);
    if(file.is_open()) {
        file << "ID: " << log->id << "\n";
        file << "Time: " << log->timestamp << "\n";
        file << "Source IP: " << log->srcIP << "\n";
        file << "Destination IP: " << log->dstIP << "\n";
        file << "Port: " << log->dstPort << "\n";
        file << "Attack: " << log->attackType << "\n";
        file << "----------------------------------------\n";
        file.close();
    }
}

void loadLogsFromFile() {
    ifstream file(LOG_FILE);
    if(!file.is_open()) return;
    
    string line;
    AttackLog* currentLog = nullptr;
    int lastId = 0;
    
    while(getline(file, line)) {
        if(line.find("ID: ") == 0) {
            currentLog = new AttackLog();
            currentLog->id = stoi(line.substr(4));
            if(currentLog->id > lastId) lastId = currentLog->id;
        }
        else if(line.find("Time: ") == 0 && currentLog) {
            currentLog->timestamp = line.substr(6);
        }
        else if(line.find("Source IP: ") == 0 && currentLog) {
            currentLog->srcIP = line.substr(11);
        }
        else if(line.find("Destination IP: ") == 0 && currentLog) {
            currentLog->dstIP = line.substr(16);
        }
        else if(line.find("Port: ") == 0 && currentLog) {
            currentLog->dstPort = stoi(line.substr(6));
        }
        else if(line.find("Attack: ") == 0 && currentLog) {
            currentLog->attackType = line.substr(8);
            logList.add(currentLog);
            currentLog = nullptr;
        }
    }
    file.close();
    
    packetCounter = lastId;
    totalPackets = lastId;
    suspiciousCount = logList.size();
}

void exportAllLogsToFile() {
    ofstream file(LOG_FILE);
    if(!file.is_open()) {
        setColor(12);
        cout << "\n  Error: Cannot create log file!\n";
        setColor(7);
        return;
    }
    
    file << "============================================================\n";
    file << "MINI-IDS - REAL TIME DATA CAPTURING TOOL\n";
    file << "Attack Log Report\n";
    file << "Generated: " << getCurrentTimestamp() << "\n";
    file << "============================================================\n\n";
    
    AttackLog** arr = logList.toArray();
    for(int i=0; i<logList.size(); i++) {
        file << "ID: " << arr[i]->id << "\n";
        file << "Time: " << arr[i]->timestamp << "\n";
        file << "Source IP: " << arr[i]->srcIP << "\n";
        file << "Destination IP: " << arr[i]->dstIP << "\n";
        file << "Port: " << arr[i]->dstPort << "\n";
        file << "Attack Type: " << arr[i]->attackType << "\n";
        file << "----------------------------------------\n";
    }
    file.close();
    delete[] arr;
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

void clearScreen() {
    system("cls");
}

void showHeader() {
    setColor(11);
    cout << "\n";
    cout << "====================================================================================================================\n";
    setColor(10);
    cout << "\n                          MINI-IDS - A Real Time Data Capturing Tool\n";
    setColor(14);
    cout << "                              REAL-TIME NETWORK INTRUSION DETECTION\n";
    
   
    cout << "\n            WARNING: THIS CAPTURES REAL NETWORK TRAFFIC\n";
    cout << "            RUN AS ADMINISTRATOR ON WINDOWS\n";
    setColor(11);
    cout << "====================================================================================================================\n";
    setColor(7);
}

void showMenu() {
    setColor(14);
    cout << "\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   MAIN MENU                                                      |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(10);
    cout << "|                                                                                                                  |\n";
    cout << "|                        [1]  LIST NETWORK INTERFACES:                                                              |\n";
    cout << "|                        [2]  START REAL-TIME CAPTURE:                                                             |\n";
    cout << "|                        [3]  VIEW STATISTICS:                                                                      |\n";
    cout << "|                        [4]  VIEW BLOCKED IP LIST :                                                                |\n";
    cout << "|                        [5]  VIEW ATTACK LOGS (LINKED LIST TRAVERSAL):                                             |\n";
    cout << "|                        [6]  LINEAR SEARCH IN LOGS :                                                               |\n";
    cout << "|                        [7]  BINARY SEARCH (SORTED BY IP):                                                         |\n";
    cout << "|                        [8]  SORTING DEMO (BUBBLE / SELECTION SORT):                                               |\n";
    cout << "|                        [9]  EXPORT ALL LOGS TO FILE:                                                              |\n";
    cout << "|                        [0]  EXIT                                                                                 |\n";
    cout << "|                                                                                                                  |\n";
    setColor(11);
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    cout << "\n  Enter your choice: ";
}

// ============================================================================
// PACKET HANDLER
// ============================================================================

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    packetCounter++;
    totalPackets++;
    
    #ifdef _WIN32
        struct ip_header {
            u_char ver_len; u_char tos; u_short len; u_short id;
            u_short off; u_char ttl; u_char proto; u_short sum;
            u_long src; u_long dst;
        };
        struct ip_header* ip = (struct ip_header*)(packet + 14);
        char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->src), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->dst), dstIP, INET_ADDRSTRLEN);
        int protocol = ip->proto;
        int ipHeaderLen = (ip->ver_len & 0x0F) * 4;
    #else
        struct iphdr* ip = (struct iphdr*)(packet + 14);
        char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->daddr), dstIP, INET_ADDRSTRLEN);
        int protocol = ip->protocol;
        int ipHeaderLen = ip->ihl * 4;
    #endif
    
    string protoName = (protocol==6) ? "TCP" : (protocol==17) ? "UDP" : (protocol==1) ? "ICMP" : "OTHER";
    int dstPort = 0;
    
    if(protocol == 6 || protocol == 17) {
        #ifdef _WIN32
            struct { u_short sport, dport; }*h = (decltype(h))(packet + 14 + ipHeaderLen);
            dstPort = ntohs(h->dport);
        #else
            if(protocol == 6) {
                struct tcphdr* tcp = (struct tcphdr*)(packet + 14 + ipHeaderLen);
                dstPort = ntohs(tcp->dest);
            } else {
                struct udphdr* udp = (struct udphdr*)(packet + 14 + ipHeaderLen);
                dstPort = ntohs(udp->dest);
            }
        #endif
    }
    
    if(blockedIPs.find(srcIP) != blockedIPs.end()) return;
    
    setColor(11);
    cout << "  #" << setw(8) << packetCounter;
    setColor(15);
    cout << " | " << setw(18) << srcIP;
    setColor(14);
    cout << " -> ";
    setColor(10);
    cout << setw(18) << dstIP;
    setColor(15);
    cout << " | " << setw(5) << protoName;
    
    if((dstPort == 22 || dstPort == 3389 || dstPort == 21) && protocol == 6) {
        attackTracker[srcIP]++;
        setColor(12);
        cout << "  [ALERT! Attempt #" << attackTracker[srcIP] << "]";
        if(attackTracker[srcIP] >= 5) {
            blockedIPs.insert(srcIP);
            suspiciousCount++;
            AttackLog* log = new AttackLog();
            log->id = logList.size() + 1;
            log->timestamp = getCurrentTimestamp();
            log->srcIP = srcIP;
            log->dstIP = dstIP;
            log->dstPort = dstPort;
            log->attackType = (dstPort==22) ? "SSH BRUTE-FORCE" : (dstPort==3389) ? "RDP BRUTE-FORCE" : "FTP BRUTE-FORCE";
            logList.add(log);
            saveLogToFile(log);
            cout << " [IP BLOCKED & LOGGED!]";
        }
    }
    setColor(7);
    cout << "\n";
}

// ============================================================================
// INTERFACE LIST
// ============================================================================

void listInterfaces() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    interfaceNames.clear();
    
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                         AVAILABLE NETWORK INTERFACES                                              |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    
    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        setColor(12);
        cout << "\n  Error: " << errbuf << "\n";
        setColor(7);
        return;
    }
    
    int idx = 1;
    for(pcap_if_t* d = alldevs; d; d = d->next) {
        interfaceNames.push_back(d->name);
        cout << "\n  [" << idx++ << "] " << d->name;
        if(d->description) {
            setColor(10);
            cout << "  -->  " << d->description;
            setColor(7);
        }
        cout << "\n";
    }
    
    if(idx == 1) {
        setColor(12);
        cout << "\n  No interfaces found! Please run as Administrator.\n";
        setColor(7);
    }
    pcap_freealldevs(alldevs);
}

// ============================================================================
// START CAPTURE
// ============================================================================

void startCapture() {
    if(interfaceNames.empty()) {
        setColor(12);
        cout << "\n  No interfaces available. Please list interfaces first (Option 1).\n";
        setColor(7);
        return;
    }
    
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                         SELECT NETWORK INTERFACE                                                 |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    
    for(size_t i = 0; i < interfaceNames.size(); i++) {
        cout << "\n  [" << (i+1) << "] " << interfaceNames[i];
    }
    
    cout << "\n\n  Enter interface number (1-" << interfaceNames.size() << "): ";
    int choice;
    cin >> choice;
    
    if(choice < 1 || choice > (int)interfaceNames.size()) {
        setColor(12);
        cout << "\n  Invalid choice!\n";
        setColor(7);
        return;
    }
    
    string iface = interfaceNames[choice - 1];
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcapHandle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
    if(!pcapHandle) {
        setColor(12);
        cout << "\n  Failed: " << errbuf << "\n  Run as Administrator!\n";
        setColor(7);
        return;
    }
    struct bpf_program fp;
    pcap_compile(pcapHandle, &fp, "ip", 0, 0);
    pcap_setfilter(pcapHandle, &fp);
    
    setColor(10);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                   [ACTIVE] REAL-TIME CAPTURE ACTIVE [ACTIVE]                                      |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "\n  Interface: " << iface << "\n";
    cout << "  Capturing REAL network traffic (NO SIMULATION)\n";
    cout << "  Press 'q' to stop capture and return to menu\n\n";
    setColor(7);
    
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                               LIVE PACKET STREAM                                                  |\n";
    cout << "|                                           (REAL NETWORK TRAFFIC)                                                 |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    
    isCapturing = true;
    
    while(isCapturing) {
        if(_kbhit()) {
            char key = tolower(_getch());
            if(key == 'q') {
                isCapturing = false;
                pcap_breakloop(pcapHandle);
                break;
            }
        }
        
        struct pcap_pkthdr* header;
        const u_char* packet;
        int result = pcap_next_ex(pcapHandle, &header, &packet);
        
        if(result == 1) {
            packetHandler(nullptr, header, packet);
        } else if(result == -1) {
            break;
        }
    }
    
    pcap_close(pcapHandle);
    pcapHandle = nullptr;
    isCapturing = false;
    
    setColor(14);
    cout << "\n  [Capture stopped. Returning to menu...]\n";
    setColor(7);
}

// ============================================================================
// STATISTICS
// ============================================================================

void showStats() {
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   STATISTICS                                                      |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    cout << "\n  Total Packets Captured (REAL)   : " << totalPackets << "\n";
    cout << "  Suspicious Attacks Detected     : " << suspiciousCount << "\n";
    cout << "  Blocked IPs                     : " << blockedIPs.size() << "\n";
    cout << "  Active Monitoring               : " << (isCapturing ? "YES" : "NO") << "\n";
    cout << "  Log File                        : " << LOG_FILE << "\n";
}

// ============================================================================
// BLOCKED IPS
// ============================================================================

void showBlocked() {
    setColor(12);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   BLOCKED IP LIST                                                 |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    if(blockedIPs.empty()) {
        cout << "\n  No IPs are currently blocked.\n";
    } else {
        cout << "\n  +----+------------------------------------------+\n";
        cout << "  | #  | IP Address                                |\n";
        cout << "  +----+------------------------------------------+\n";
        int i = 1;
        for(string ip : blockedIPs) {
            cout << "  | " << setw(2) << i++ << " | " << setw(40) << ip << " |\n";
        }
        cout << "  +----+------------------------------------------+\n";
    }
    cout << "\n  Total Blocked IPs: " << blockedIPs.size() << "\n";
}

// ============================================================================
// VIEW LOGS
// ============================================================================

void displayLog(AttackLog* log) {
    setColor(14);
    cout << "  | " << setw(4) << log->id;
    setColor(7);
    cout << " | " << log->timestamp.substr(0,19);
    setColor(10);
    cout << " | " << setw(18) << log->srcIP;
    setColor(12);
    cout << " | " << setw(22) << log->attackType;
    setColor(7);
    cout << " | " << setw(6) << log->dstPort << " |\n";
}

void viewLogs() {
    setColor(13);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   ATTACK LOGS                                                     |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    if(logList.size() == 0) {
        cout << "\n  No attacks detected yet.\n";
    } else {
        cout << "\n  +------+---------------------+--------------------+------------------------+--------+\n";
        cout << "  | ID   | Timestamp           | Source IP           | Attack Type            | Port   |\n";
        cout << "  +------+---------------------+--------------------+------------------------+--------+\n";
        logList.traverse(displayLog);
        cout << "  +------+---------------------+--------------------+------------------------+--------+\n";
    }
    cout << "\n  Total Attacks: " << logList.size() << "\n";
}

// ============================================================================
// LINEAR SEARCH
// ============================================================================

void linearSearch() {
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   LINEAR SEARCH                                                   |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    string ip;
    cout << "\n  Enter IP address: ";
    cin >> ip;
    AttackLog* found = logList.linearSearch(ip);
    if(found) {
        setColor(10);
        cout << "\n  [FOUND] Attack found!\n";
        setColor(7);
        cout << "     Attack Type: " << found->attackType << "\n";
        cout << "     Time: " << found->timestamp << "\n";
        cout << "     Port: " << found->dstPort << "\n";
    } else {
        setColor(12);
        cout << "\n  [NOT FOUND] IP " << ip << " not found in logs.\n";
        setColor(7);
    }
}

// ============================================================================
// BINARY SEARCH
// ============================================================================

void binarySearch() {
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   BINARY SEARCH                                                   |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    if(logList.size() == 0) {
        cout << "\n  No logs to search.\n";
        return;
    }
    
    AttackLog** arr = logList.toArray();
    int n = logList.size();
    for(int i=0; i<n-1; i++)
        for(int j=0; j<n-i-1; j++)
            if(arr[j]->srcIP > arr[j+1]->srcIP)
                swap(arr[j], arr[j+1]);
    
    string ip;
    cout << "\n  Enter IP address: ";
    cin >> ip;
    
    int left=0, right=n-1, pos=-1;
    while(left <= right) {
        int mid = (left+right)/2;
        if(arr[mid]->srcIP == ip) { pos=mid; break; }
        else if(arr[mid]->srcIP < ip) left=mid+1;
        else right=mid-1;
    }
    
    if(pos != -1) {
        setColor(10);
        cout << "\n  [FOUND] IP found at index " << pos << "\n";
        setColor(7);
        cout << "     Attack Type: " << arr[pos]->attackType << "\n";
        cout << "     Timestamp: " << arr[pos]->timestamp << "\n";
        cout << "     Port: " << arr[pos]->dstPort << "\n";
    } else {
        setColor(12);
        cout << "\n  [NOT FOUND] IP " << ip << " not found.\n";
        setColor(7);
    }
    delete[] arr;
}

// ============================================================================
// SORTING DEMO
// ============================================================================

void sortingDemo() {
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   SORTING DEMO                                                    |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    if(logList.size() == 0) {
        cout << "\n  No logs to sort.\n";
        return;
    }
    cout << "\n  1. Bubble Sort (by Time)\n";
    cout << "  2. Selection Sort (by Port)\n";
    cout << "\n  Choose algorithm: ";
    int ch; cin >> ch;
    if(ch==1) {
        logList.bubbleSortByTime();
        setColor(10);
        cout << "\n  [COMPLETED] Bubble Sort completed! Sorted by timestamp.\n";
    } else if(ch==2) {
        logList.selectionSortByPort();
        setColor(10);
        cout << "\n  [COMPLETED] Selection Sort completed! Sorted by destination port.\n";
    } else {
        setColor(12);
        cout << "\n  Invalid choice!\n";
        setColor(7);
        return;
    }
    viewLogs();
}

// ============================================================================
// EXPORT
// ============================================================================

void exportLogs() {
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   EXPORT ALL LOGS                                                 |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    
    exportAllLogsToFile();
    
    setColor(10);
    cout << "\n  [EXPORTED] All logs exported to " << LOG_FILE << "\n";
    cout << "  Total " << logList.size() << " attack records saved.\n";
    setColor(7);
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

bool authenticate() {
    string pass;
    setColor(11);
    cout << "\n+------------------------------------------------------------------------------------------------------------------+\n";
    cout << "|                                                   ACCESS CONTROL                                                  |\n";
    cout << "+------------------------------------------------------------------------------------------------------------------+\n";
    setColor(7);
    cout << "\n  Password: ";
    char ch;
    pass = "";
    while((ch = _getch()) != '\r') {
        if(ch == '\b' && !pass.empty()) {
            pass.pop_back();
            cout << "\b \b";
        } else if(ch != '\b') {
            pass += ch;
            cout << '*';
        }
    }
    cout << "\n";
    return pass == "porosh";
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    #ifdef _WIN32
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
    #endif
    
    loadLogsFromFile();
    
    if(!authenticate()) {
        setColor(12);
        cout << "\n  Access Denied!\n";
        setColor(7);
        return 0;
    }
    
    while(true) {
        clearScreen();
        showHeader();
        showMenu();
        int choice;
        cin >> choice;
        
        if(choice == 1) {
            listInterfaces();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 2) {
            startCapture();
        }
        else if(choice == 3) {
            showStats();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 4) {
            showBlocked();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 5) {
            viewLogs();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 6) {
            linearSearch();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 7) {
            binarySearch();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 8) {
            sortingDemo();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 9) {
            exportLogs();
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
        else if(choice == 0) {
            if(pcapHandle) pcap_close(pcapHandle);
            setColor(10);
            cout << "\n  Shutting down... Goodbye!\n";
            setColor(7);
            #ifdef _WIN32
                WSACleanup();
            #endif
            return 0;
        }
        else {
            setColor(12);
            cout << "\n  Invalid choice!\n";
            setColor(7);
            cout << "\n  Press any key to continue...";
            cin.ignore();
            cin.get();
        }
    }
    return 0;
}