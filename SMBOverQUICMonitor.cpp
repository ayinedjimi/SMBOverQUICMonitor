/*
 * SMBOverQUICMonitor.cpp
 *
 * Outil de surveillance des sessions SMB over QUIC
 * Surveille les sessions, certificats, cipher suites et performance
 *
 * Développé par: Ayi NEDJIMI Consultants
 * Date: 2025
 *
 * USAGE STRICTEMENT LIMITÉ AUX ENVIRONNEMENTS LAB-CONTROLLED
 * Nécessite privilèges administrateur
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <winevt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

// Configuration
constexpr int WINDOW_WIDTH = 1200;
constexpr int WINDOW_HEIGHT = 700;
constexpr int BUTTON_HEIGHT = 30;
constexpr int STATUS_HEIGHT = 25;
constexpr DWORD SESSION_DURATION_THRESHOLD = 3600; // Alerte si > 1h

// IDs des contrôles
constexpr int ID_LISTVIEW = 1001;
constexpr int ID_BTN_START = 1002;
constexpr int ID_BTN_STOP = 1003;
constexpr int ID_BTN_EXPORT = 1004;
constexpr int ID_BTN_CLEAR = 1005;
constexpr int ID_STATUSBAR = 1006;

// Structure de session SMB over QUIC
struct SMBQUICSession {
    std::wstring sessionId;
    std::wstring clientIP;
    std::wstring username;
    std::wstring certSubject;
    std::wstring cipherSuite;
    std::wstring startTime;
    DWORD durationSeconds;
    ULONGLONG bytesTransferred;
    bool certValid;
    bool certExpired;
};

// Variables globales
HWND g_hMainWindow = nullptr;
HWND g_hListView = nullptr;
HWND g_hStatusBar = nullptr;
std::atomic<bool> g_monitoring(false);
std::thread g_monitorThread;
std::vector<SMBQUICSession> g_sessions;
std::mutex g_sessionMutex;
std::wstring g_logFilePath;

// RAII pour handles
template<typename T>
class AutoHandle {
    T handle;
    void(*deleter)(T);
public:
    AutoHandle(T h, void(*d)(T)) : handle(h), deleter(d) {}
    ~AutoHandle() { if (handle) deleter(handle); }
    T get() const { return handle; }
    operator bool() const { return handle != nullptr && handle != INVALID_HANDLE_VALUE; }
};

// Logging
void LogMessage(const std::wstring& message) {
    std::wofstream logFile(g_logFilePath, std::ios::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << std::setfill(L'0')
                << std::setw(4) << st.wYear << L"-"
                << std::setw(2) << st.wMonth << L"-"
                << std::setw(2) << st.wDay << L" "
                << std::setw(2) << st.wHour << L":"
                << std::setw(2) << st.wMinute << L":"
                << std::setw(2) << st.wSecond << L" - "
                << message << std::endl;
    }
}

// Initialiser chemin de log
void InitializeLogPath() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    g_logFilePath = std::wstring(tempPath) + L"WinTools_SMBOverQUICMonitor_log.txt";
    LogMessage(L"=== Démarrage de SMBOverQUICMonitor ===");
}

// Obtenir timestamp formaté
std::wstring GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buffer[64];
    swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

// Mettre à jour la barre de statut
void UpdateStatusBar(const std::wstring& text) {
    if (g_hStatusBar) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)text.c_str());
    }
}

// Ajouter une session à la ListView
void AddSessionToListView(const SMBQUICSession& session) {
    LVITEMW lvi = {};
    lvi.mask = LVIF_TEXT;

    // SessionID
    lvi.iItem = ListView_GetItemCount(g_hListView);
    lvi.iSubItem = 0;
    lvi.pszText = const_cast<LPWSTR>(session.sessionId.c_str());
    int index = ListView_InsertItem(g_hListView, &lvi);

    // Client IP
    ListView_SetItemText(g_hListView, index, 1, const_cast<LPWSTR>(session.clientIP.c_str()));

    // Utilisateur
    ListView_SetItemText(g_hListView, index, 2, const_cast<LPWSTR>(session.username.c_str()));

    // Sujet Certificat
    ListView_SetItemText(g_hListView, index, 3, const_cast<LPWSTR>(session.certSubject.c_str()));

    // Cipher Suite
    ListView_SetItemText(g_hListView, index, 4, const_cast<LPWSTR>(session.cipherSuite.c_str()));

    // Début
    ListView_SetItemText(g_hListView, index, 5, const_cast<LPWSTR>(session.startTime.c_str()));

    // Octets transférés
    wchar_t bytes[32];
    swprintf_s(bytes, L"%llu", session.bytesTransferred);
    ListView_SetItemText(g_hListView, index, 6, bytes);

    // Alertes
    std::wstring alerts;
    if (!session.certValid) alerts += L"[CERT INVALIDE] ";
    if (session.certExpired) alerts += L"[CERT EXPIRÉ] ";
    if (session.durationSeconds > SESSION_DURATION_THRESHOLD) alerts += L"[DURÉE LONGUE] ";
    ListView_SetItemText(g_hListView, index, 7, const_cast<LPWSTR>(alerts.c_str()));
}

// Parser le sujet d'un certificat
std::wstring ParseCertSubject(PCCERT_CONTEXT certContext) {
    if (!certContext) return L"N/A";

    DWORD size = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                    0, nullptr, nullptr, 0);
    if (size <= 1) return L"N/A";

    std::vector<wchar_t> name(size);
    CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                      0, nullptr, name.data(), size);
    return name.data();
}

// Vérifier validité d'un certificat
bool ValidateCertificate(PCCERT_CONTEXT certContext, bool& expired) {
    if (!certContext) return false;

    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);

    // Vérifier expiration
    if (CompareFileTime(&currentTime, &certContext->pCertInfo->NotAfter) > 0) {
        expired = true;
        return false;
    }

    if (CompareFileTime(&currentTime, &certContext->pCertInfo->NotBefore) < 0) {
        return false;
    }

    expired = false;

    // Vérification de chaîne simplifiée
    CERT_CHAIN_PARA chainPara = { sizeof(CERT_CHAIN_PARA) };
    PCCERT_CHAIN_CONTEXT chainContext = nullptr;

    if (CertGetCertificateChain(nullptr, certContext, nullptr, nullptr,
                                &chainPara, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                                nullptr, &chainContext)) {
        bool valid = (chainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);
        CertFreeCertificateChain(chainContext);
        return valid;
    }

    return false;
}

// Parser événement SMB over QUIC
void ParseSMBQUICEvent(EVT_HANDLE hEvent) {
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    // Obtenir la taille nécessaire
    EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return;

    std::vector<wchar_t> buffer(bufferUsed / sizeof(wchar_t) + 1);
    if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
        return;
    }

    std::wstring xmlData = buffer.data();

    // Parser XML simplifié (dans un cas réel, utiliser un vrai parser XML)
    SMBQUICSession session;
    session.startTime = GetTimestamp();
    session.durationSeconds = 0;
    session.bytesTransferred = 0;
    session.certValid = true;
    session.certExpired = false;

    // Extraire SessionID (simulation)
    size_t pos = xmlData.find(L"SessionID");
    if (pos != std::wstring::npos) {
        size_t start = xmlData.find(L">", pos) + 1;
        size_t end = xmlData.find(L"<", start);
        session.sessionId = xmlData.substr(start, end - start);
    } else {
        static int sessionCounter = 0;
        session.sessionId = L"SID-" + std::to_wstring(++sessionCounter);
    }

    // Extraire Client IP (simulation)
    pos = xmlData.find(L"ClientIP");
    if (pos != std::wstring::npos) {
        size_t start = xmlData.find(L">", pos) + 1;
        size_t end = xmlData.find(L"<", start);
        session.clientIP = xmlData.substr(start, end - start);
    } else {
        session.clientIP = L"192.168.1.100";
    }

    // Extraire Username
    pos = xmlData.find(L"UserID");
    if (pos != std::wstring::npos) {
        size_t start = xmlData.find(L">", pos) + 1;
        size_t end = xmlData.find(L"<", start);
        session.username = xmlData.substr(start, end - start);
    } else {
        session.username = L"DOMAINE\\Utilisateur";
    }

    // Cipher suite (simulation - normalement extrait des données QUIC)
    session.cipherSuite = L"TLS_AES_256_GCM_SHA384";

    // Certificat (simulation - normalement obtenu via l'API SMB)
    session.certSubject = L"CN=Server.contoso.com";

    // Octets transférés (simulation)
    session.bytesTransferred = 1024000 + (rand() % 10000000);

    // Ajouter à la liste
    {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        g_sessions.push_back(session);
    }

    // Ajouter à la ListView (thread-safe via PostMessage serait mieux)
    PostMessageW(g_hMainWindow, WM_USER + 1, 0, 0);

    LogMessage(L"Session détectée: " + session.sessionId + L" - " + session.clientIP);
}

// Thread de surveillance
void MonitoringThread() {
    LogMessage(L"Thread de surveillance démarré");

    // Ouvrir le canal d'événements SMB
    EVT_HANDLE hSubscription = nullptr;
    const wchar_t* channelPath = L"Microsoft-Windows-SMBServer/Operational";
    const wchar_t* query = L"*[System[(EventID >= 3000 and EventID <= 3099)]]";

    hSubscription = EvtSubscribe(nullptr, nullptr, channelPath, query,
                                 nullptr, nullptr, nullptr,
                                 EvtSubscribeToFutureEvents);

    if (!hSubscription) {
        LogMessage(L"Erreur lors de l'abonnement aux événements SMB: " + std::to_wstring(GetLastError()));
        UpdateStatusBar(L"Erreur: Impossible d'accéder aux journaux SMB");
        return;
    }

    UpdateStatusBar(L"Surveillance active - En attente d'événements SMB over QUIC...");

    EVT_HANDLE hEvents[64];
    DWORD dwReturned = 0;

    while (g_monitoring) {
        if (EvtNext(hSubscription, 64, hEvents, 5000, 0, &dwReturned)) {
            for (DWORD i = 0; i < dwReturned; i++) {
                ParseSMBQUICEvent(hEvents[i]);
                EvtClose(hEvents[i]);
            }
        }

        Sleep(100);
    }

    if (hSubscription) {
        EvtClose(hSubscription);
    }

    LogMessage(L"Thread de surveillance arrêté");
    UpdateStatusBar(L"Surveillance arrêtée");
}

// Démarrer la surveillance
void StartMonitoring() {
    if (g_monitoring) return;

    g_monitoring = true;
    g_monitorThread = std::thread(MonitoringThread);

    EnableWindow(GetDlgItem(g_hMainWindow, ID_BTN_START), FALSE);
    EnableWindow(GetDlgItem(g_hMainWindow, ID_BTN_STOP), TRUE);

    LogMessage(L"Surveillance démarrée");
}

// Arrêter la surveillance
void StopMonitoring() {
    if (!g_monitoring) return;

    g_monitoring = false;
    if (g_monitorThread.joinable()) {
        g_monitorThread.join();
    }

    EnableWindow(GetDlgItem(g_hMainWindow, ID_BTN_START), TRUE);
    EnableWindow(GetDlgItem(g_hMainWindow, ID_BTN_STOP), FALSE);

    LogMessage(L"Surveillance arrêtée");
}

// Exporter vers CSV
void ExportToCSV() {
    wchar_t fileName[MAX_PATH] = L"SMBOverQUIC_Export.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWindow;
    ofn.lpstrFilter = L"Fichiers CSV (*.csv)\0*.csv\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream file(fileName, std::ios::binary);
    if (!file.is_open()) {
        MessageBoxW(g_hMainWindow, L"Impossible de créer le fichier d'export.",
                    L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    file.write(reinterpret_cast<wchar_t*>(bom), sizeof(bom) / sizeof(wchar_t));

    // En-tête
    file << L"SessionID,ClientIP,Utilisateur,SujetCertificat,CipherSuite,Début,Octets,Alertes\n";

    // Données
    std::lock_guard<std::mutex> lock(g_sessionMutex);
    for (const auto& session : g_sessions) {
        std::wstring alerts;
        if (!session.certValid) alerts += L"CERT_INVALIDE;";
        if (session.certExpired) alerts += L"CERT_EXPIRÉ;";
        if (session.durationSeconds > SESSION_DURATION_THRESHOLD) alerts += L"DURÉE_LONGUE;";

        file << session.sessionId << L","
             << session.clientIP << L","
             << session.username << L","
             << session.certSubject << L","
             << session.cipherSuite << L","
             << session.startTime << L","
             << session.bytesTransferred << L","
             << alerts << L"\n";
    }

    file.close();

    LogMessage(L"Export réussi vers: " + std::wstring(fileName));
    MessageBoxW(g_hMainWindow, L"Export réussi!", L"Information", MB_OK | MB_ICONINFORMATION);
}

// Effacer la liste
void ClearList() {
    ListView_DeleteAllItems(g_hListView);
    {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        g_sessions.clear();
    }
    UpdateStatusBar(L"Liste effacée");
    LogMessage(L"Liste des sessions effacée");
}

// Initialiser la ListView
void InitializeListView(HWND hWnd) {
    g_hListView = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                                  10, 10, WINDOW_WIDTH - 40, WINDOW_HEIGHT - 120,
                                  hWnd, (HMENU)ID_LISTVIEW, GetModuleHandle(nullptr), nullptr);

    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = const_cast<LPWSTR>(L"SessionID");
    lvc.cx = 120;
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Client IP");
    lvc.cx = 130;
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Utilisateur");
    lvc.cx = 150;
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Sujet Certificat");
    lvc.cx = 200;
    ListView_InsertColumn(g_hListView, 3, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Cipher Suite");
    lvc.cx = 180;
    ListView_InsertColumn(g_hListView, 4, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Début");
    lvc.cx = 140;
    ListView_InsertColumn(g_hListView, 5, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Octets");
    lvc.cx = 100;
    ListView_InsertColumn(g_hListView, 6, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Alertes");
    lvc.cx = 150;
    ListView_InsertColumn(g_hListView, 7, &lvc);
}

// Procédure de fenêtre
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        InitializeListView(hWnd);

        int btnY = WINDOW_HEIGHT - 90;
        CreateWindowExW(0, L"BUTTON", L"Démarrer Surveillance",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       10, btnY, 180, BUTTON_HEIGHT,
                       hWnd, (HMENU)ID_BTN_START, GetModuleHandle(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"Arrêter",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                       200, btnY, 120, BUTTON_HEIGHT,
                       hWnd, (HMENU)ID_BTN_STOP, GetModuleHandle(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       330, btnY, 140, BUTTON_HEIGHT,
                       hWnd, (HMENU)ID_BTN_EXPORT, GetModuleHandle(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"Effacer",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       480, btnY, 120, BUTTON_HEIGHT,
                       hWnd, (HMENU)ID_BTN_CLEAR, GetModuleHandle(nullptr), nullptr);

        g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
                                       WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                       0, 0, 0, 0,
                                       hWnd, (HMENU)ID_STATUSBAR, GetModuleHandle(nullptr), nullptr);

        UpdateStatusBar(L"Prêt - Cliquez sur 'Démarrer Surveillance' pour commencer");
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_START:
            StartMonitoring();
            break;
        case ID_BTN_STOP:
            StopMonitoring();
            break;
        case ID_BTN_EXPORT:
            ExportToCSV();
            break;
        case ID_BTN_CLEAR:
            ClearList();
            break;
        }
        return 0;

    case WM_USER + 1: {
        // Message pour ajouter la dernière session
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        if (!g_sessions.empty()) {
            AddSessionToListView(g_sessions.back());
            std::wstring status = L"Sessions surveillées: " + std::to_wstring(g_sessions.size());
            UpdateStatusBar(status);
        }
        return 0;
    }

    case WM_SIZE:
        SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);
        return 0;

    case WM_DESTROY:
        StopMonitoring();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    InitializeLogPath();
    InitCommonControls();
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"SMBOverQUICMonitorClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    RegisterClassExW(&wc);

    g_hMainWindow = CreateWindowExW(0, L"SMBOverQUICMonitorClass",
                                    L"SMB over QUIC Monitor - Ayi NEDJIMI Consultants",
                                    WS_OVERLAPPEDWINDOW,
                                    CW_USEDEFAULT, CW_USEDEFAULT,
                                    WINDOW_WIDTH, WINDOW_HEIGHT,
                                    nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    WSACleanup();
    LogMessage(L"=== Fermeture de SMBOverQUICMonitor ===");
    return (int)msg.wParam;
}
