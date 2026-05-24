#include <Arduino.h>
#include <FS.h>
#include <SPIFFS.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256

namespace SerialUi {
    constexpr char CLEAR[] = "\033[2J\033[H";
    constexpr char RESET[] = "\033[0m";
    constexpr char BOLD[] = "\033[1m";
    constexpr char DIM[] = "\033[2m";
    constexpr char RED[] = "\033[31m";
    constexpr char GREEN[] = "\033[32m";
    constexpr char YELLOW[] = "\033[33m";
    constexpr char BLUE[] = "\033[34m";
    constexpr char CYAN[] = "\033[36m";
    constexpr char WHITE[] = "\033[37m";
    constexpr char GRAY[] = "\033[90m";
}

namespace Storage {
    constexpr char DEFAULT_PROFILE[] = "backup";
    constexpr char DEFAULT_STATUS[] = "VOLATILE";
    constexpr char DIR_ROOT[] = "/";
    constexpr char FILE_PREFIX[] = "cfg_";
    constexpr char FILE_SUFFIX[] = ".txt";
    constexpr char DIRTY_STATUS[] = "UNSAVED";
    constexpr size_t PROFILE_NAME_MAX = 16;
    constexpr size_t CONFIG_PATH_MAX = 32;
}

struct Pump {
    const char *label;
    bool enabled;
};

struct Valve {
    const char *label;
    bool open;
};

struct Conveyor {
    bool running;
    uint8_t speedPct;
};

struct Heater {
    bool enabled;
    float targetC;
    float currentC;
};

struct PlantMetrics {
    float tankLevelPct;
    float pressureBar;
    float flowPct;
};

struct AlarmState {
    bool active;
    char message[40];
};

struct PanelConfig {
    bool pumpAEnabled;
    bool pumpBEnabled;
    bool intakeOpen;
    bool bypassOpen;
    bool conveyorRunning;
    uint8_t conveyorSpeedPct;
    bool heaterEnabled;
    float heaterTargetC;
    float heaterCurrentC;
    float tankLevelPct;
    float pressureBar;
    float flowPct;
    char mode[16];
};

enum class DeviceId {
    Unknown,
    PumpA,
    PumpB,
    IntakeValve,
    BypassValve,
    Conveyor,
    Heater
};

Pump pumpA{"PUMP A", false};
Pump pumpB{"PUMP B", false};
Valve intakeValve{"INTAKE", false};
Valve bypassValve{"BYPASS", true};
Conveyor conveyor{false, 45};
Heater heater{false, 110.0f, 24.0f};
PlantMetrics metrics{48.0f, 1.3f, 0.0f};
AlarmState alarmState{false, "SYSTEM NOMINAL"};

char modeLabel[16] = "IDLE";
char inputBuffer[96];
size_t inputLength = 0;
bool fileSystemReady = false;
char backupLabel[Storage::PROFILE_NAME_MAX + 1] = "VOLATILE";
char noticeLine[96] = "Type 'help' for available commands.";
bool pendingLoadConfirmation = false;
PanelConfig pendingLoadConfig{};
char pendingLoadProfile[Storage::PROFILE_NAME_MAX + 1] = "";
char pendingLoadPath[Storage::CONFIG_PATH_MAX] = "";

unsigned long lastModelMs = 0;
unsigned long bootMs = 0;

void evaluateAlarmConditions();
void drawDashboard();

float clampf(float value, float low, float high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

void setMode(const char *mode) {
    snprintf(modeLabel, sizeof(modeLabel), "%s", mode);
}

void setAlarmMessage(const char *message) {
    snprintf(alarmState.message, sizeof(alarmState.message), "%s", message);
}

void markConfigDirty() {
    snprintf(backupLabel, sizeof(backupLabel), "%s", Storage::DIRTY_STATUS);
}

void setBackupLabel(const char *label) {
    snprintf(backupLabel, sizeof(backupLabel), "%s", label);
}

void setNoticef(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(noticeLine, sizeof(noticeLine), format, args);
    va_end(args);
}

void noteManualChange() {
    setMode("MANUAL");
    markConfigDirty();
}

bool tokenEquals(const char *a, const char *b) {
    return strcasecmp(a, b) == 0;
}

bool tokenStarts(const char *a, const char *b) {
    while (*a != '\0' && *b != '\0') {
        if (tolower(static_cast<unsigned char>(*a)) != tolower(static_cast<unsigned char>(*b))) {
            return false;
        }
        ++a;
        ++b;
    }
    return *b == '\0';
}

void trimWhitespace(char *text) {
    size_t length = strlen(text);
    while (length > 0 && isspace(static_cast<unsigned char>(text[length - 1]))) {
        text[--length] = '\0';
    }

    size_t start = 0;
    while (text[start] != '\0' && isspace(static_cast<unsigned char>(text[start]))) {
        ++start;
    }

    if (start > 0) {
        memmove(text, text + start, strlen(text + start) + 1);
    }
}

bool sanitizeProfileName(const char *rawName, char *cleanName, size_t cleanNameSize) {
    const char *source = rawName;
    size_t written = 0;

    if (cleanNameSize == 0) {
        return false;
    }

    if (source == nullptr || source[0] == '\0') {
        source = Storage::DEFAULT_PROFILE;
    }

    for (const char *cursor = source; *cursor != '\0'; ++cursor) {
        const unsigned char value = static_cast<unsigned char>(*cursor);
        if (!isalnum(value) && value != '-' && value != '_') {
            return false;
        }
        if (written >= cleanNameSize - 1) {
            return false;
        }
        cleanName[written++] = static_cast<char>(tolower(value));
    }

    if (written == 0) {
        return false;
    }

    cleanName[written] = '\0';
    return true;
}

void buildConfigPath(const char *profileName, char *path, size_t pathSize) {
    snprintf(path, pathSize, "/%s%s%s", Storage::FILE_PREFIX, profileName, Storage::FILE_SUFFIX);
}

void captureConfiguration(PanelConfig &config) {
    config.pumpAEnabled = pumpA.enabled;
    config.pumpBEnabled = pumpB.enabled;
    config.intakeOpen = intakeValve.open;
    config.bypassOpen = bypassValve.open;
    config.conveyorRunning = conveyor.running;
    config.conveyorSpeedPct = conveyor.speedPct;
    config.heaterEnabled = heater.enabled;
    config.heaterTargetC = heater.targetC;
    config.heaterCurrentC = heater.currentC;
    config.tankLevelPct = metrics.tankLevelPct;
    config.pressureBar = metrics.pressureBar;
    config.flowPct = metrics.flowPct;
    snprintf(config.mode, sizeof(config.mode), "%s", modeLabel);
}

void applyConfiguration(const PanelConfig &config) {
    pumpA.enabled = config.pumpAEnabled;
    pumpB.enabled = config.pumpBEnabled;
    intakeValve.open = config.intakeOpen;
    bypassValve.open = config.bypassOpen;
    conveyor.running = config.conveyorRunning && config.conveyorSpeedPct > 0;
    conveyor.speedPct = static_cast<uint8_t>(clampf(config.conveyorSpeedPct, 0.0f, 100.0f));
    heater.enabled = config.heaterEnabled;
    heater.targetC = clampf(config.heaterTargetC, 40.0f, 220.0f);
    heater.currentC = clampf(config.heaterCurrentC, 18.0f, 240.0f);
    metrics.tankLevelPct = clampf(config.tankLevelPct, 0.0f, 100.0f);
    metrics.pressureBar = clampf(config.pressureBar, 0.0f, 10.0f);
    metrics.flowPct = clampf(config.flowPct, 0.0f, 100.0f);
    setMode(config.mode);
    evaluateAlarmConditions();
}

bool extractProfileName(const char *path, char *profileName, size_t profileNameSize) {
    const char *base = strrchr(path, '/');
    const char *fileName = base == nullptr ? path : base + 1;
    const size_t prefixLength = strlen(Storage::FILE_PREFIX);
    const size_t suffixLength = strlen(Storage::FILE_SUFFIX);
    const size_t totalLength = strlen(fileName);

    if (profileNameSize == 0) {
        return false;
    }
    if (!tokenStarts(fileName, Storage::FILE_PREFIX)) {
        return false;
    }
    if (totalLength <= prefixLength + suffixLength) {
        return false;
    }
    if (!tokenEquals(fileName + totalLength - suffixLength, Storage::FILE_SUFFIX)) {
        return false;
    }

    const size_t profileLength = totalLength - prefixLength - suffixLength;
    const size_t safeLength = profileLength < profileNameSize - 1 ? profileLength : profileNameSize - 1;
    memcpy(profileName, fileName + prefixLength, safeLength);
    profileName[safeLength] = '\0';
    return true;
}

bool saveConfiguration(const char *rawName) {
    PanelConfig config;
    char profileName[Storage::PROFILE_NAME_MAX + 1];
    char path[Storage::CONFIG_PATH_MAX];

    if (!fileSystemReady) {
        setNoticef("Storage unavailable. Save/load is disabled.");
        return false;
    }
    if (!sanitizeProfileName(rawName, profileName, sizeof(profileName))) {
        setNoticef("Backup name must be 1-16 chars using letters, numbers, '-' or '_'.");
        return false;
    }

    captureConfiguration(config);
    buildConfigPath(profileName, path, sizeof(path));
    SPIFFS.remove(path);

    File file = SPIFFS.open(path, FILE_WRITE);
    if (!file) {
        setNoticef("Could not open %s for writing.", path);
        return false;
    }

    file.printf("version=1\n");
    file.printf("mode=%s\n", config.mode);
    file.printf("pumpA=%d\n", config.pumpAEnabled ? 1 : 0);
    file.printf("pumpB=%d\n", config.pumpBEnabled ? 1 : 0);
    file.printf("intake=%d\n", config.intakeOpen ? 1 : 0);
    file.printf("bypass=%d\n", config.bypassOpen ? 1 : 0);
    file.printf("conveyor=%d\n", config.conveyorRunning ? 1 : 0);
    file.printf("speed=%u\n", config.conveyorSpeedPct);
    file.printf("heater=%d\n", config.heaterEnabled ? 1 : 0);
    file.printf("target=%.2f\n", config.heaterTargetC);
    file.printf("current=%.2f\n", config.heaterCurrentC);
    file.printf("level=%.2f\n", config.tankLevelPct);
    file.printf("pressure=%.2f\n", config.pressureBar);
    file.printf("flow=%.2f\n", config.flowPct);
    file.close();

    setBackupLabel(profileName);
    setNoticef("Saved backup to %s.", path);
    return true;
}

bool readConfiguration(const char *rawName,
        PanelConfig &config,
        char *profileName,
        size_t profileNameSize,
        char *path,
        size_t pathSize,
        bool printRaw) {
    bool versionOk = false;

    if (!fileSystemReady) {
        setNoticef("Storage unavailable. Save/load is disabled.");
        return false;
    }
    if (!sanitizeProfileName(rawName, profileName, profileNameSize)) {
        setNoticef("Backup name must be 1-16 chars using letters, numbers, '-' or '_'.");
        return false;
    }

    buildConfigPath(profileName, path, pathSize);
    if (!SPIFFS.exists(path)) {
        setNoticef("Backup not found: %s.", path);
        return false;
    }

    File file = SPIFFS.open(path, FILE_READ);
    if (!file) {
        setNoticef("Could not open %s for reading.", path);
        return false;
    }

    captureConfiguration(config);

    while (file.available()) {
        char line[96];
        size_t lineLength = file.readBytesUntil('\n', line, sizeof(line) - 1);
        line[lineLength] = '\0';
        if (printRaw) {
            Serial.println(line);
        }
        if (lineLength == 0) {
            continue;
        }
        trimWhitespace(line);
        if (line[0] == '\0') {
            continue;
        }

        char *separator = strchr(line, '=');
        if (separator == nullptr) {
            continue;
        }

        *separator = '\0';
        char *value = separator + 1;
        trimWhitespace(line);
        trimWhitespace(value);

        if (tokenEquals(line, "version")) {
            versionOk = tokenEquals(value, "1");
        } else if (tokenEquals(line, "mode")) {
            snprintf(config.mode, sizeof(config.mode), "%s", value);
        } else if (tokenEquals(line, "pumpA")) {
            config.pumpAEnabled = atoi(value) != 0;
        } else if (tokenEquals(line, "pumpB")) {
            config.pumpBEnabled = atoi(value) != 0;
        } else if (tokenEquals(line, "intake")) {
            config.intakeOpen = atoi(value) != 0;
        } else if (tokenEquals(line, "bypass")) {
            config.bypassOpen = atoi(value) != 0;
        } else if (tokenEquals(line, "conveyor")) {
            config.conveyorRunning = atoi(value) != 0;
        } else if (tokenEquals(line, "speed")) {
            config.conveyorSpeedPct = static_cast<uint8_t>(clampf(atoi(value), 0.0f, 100.0f));
        } else if (tokenEquals(line, "heater")) {
            config.heaterEnabled = atoi(value) != 0;
        } else if (tokenEquals(line, "target")) {
            config.heaterTargetC = clampf(static_cast<float>(atof(value)), 40.0f, 220.0f);
        } else if (tokenEquals(line, "current")) {
            config.heaterCurrentC = clampf(static_cast<float>(atof(value)), 18.0f, 240.0f);
        } else if (tokenEquals(line, "level")) {
            config.tankLevelPct = clampf(static_cast<float>(atof(value)), 0.0f, 100.0f);
        } else if (tokenEquals(line, "pressure")) {
            config.pressureBar = clampf(static_cast<float>(atof(value)), 0.0f, 10.0f);
        } else if (tokenEquals(line, "flow")) {
            config.flowPct = clampf(static_cast<float>(atof(value)), 0.0f, 100.0f);
        }
    }

    file.close();

    if (printRaw) {
        Serial.println();
    }

    if (!versionOk) {
        setNoticef("Backup %s is not a supported panel config.", path);
        return false;
    }

    return true;
}

void printLoadConfirmationPrompt() {
    Serial.printf("Apply backup '%s'? [y/N]: ", pendingLoadProfile);
}

void loadConfiguration(const char *rawName) {
    pendingLoadConfirmation = false;
    pendingLoadProfile[0] = '\0';
    pendingLoadPath[0] = '\0';

    if (!readConfiguration(rawName,
                pendingLoadConfig,
                pendingLoadProfile,
                sizeof(pendingLoadProfile),
                pendingLoadPath,
                sizeof(pendingLoadPath),
                true)) {
        drawDashboard();
        return;
    }

    pendingLoadConfirmation = true;
    printLoadConfirmationPrompt();
}

void handleLoadConfirmation(char *line) {
    trimWhitespace(line);

    if (line[0] == '\0' || tokenEquals(line, "n") || tokenEquals(line, "no")) {
        pendingLoadConfirmation = false;
        setNoticef("Load canceled for %s.", pendingLoadProfile[0] == '\0' ? "backup" : pendingLoadProfile);
        drawDashboard();
        return;
    }

    if (tokenEquals(line, "y") || tokenEquals(line, "yes")) {
        pendingLoadConfirmation = false;
        applyConfiguration(pendingLoadConfig);
        setBackupLabel(pendingLoadProfile);
        setNoticef("Loaded backup from %s.", pendingLoadPath);
        drawDashboard();
        return;
    }

    Serial.println("Please answer 'yes' or 'no'.");
    printLoadConfirmationPrompt();
}

void listConfigurations() {
    if (!fileSystemReady) {
        Serial.println("Storage unavailable. Save/load is disabled.");
        return;
    }

    File root = SPIFFS.open(Storage::DIR_ROOT);
    if (!root) {
        Serial.println("Could not open storage root.");
        return;
    }

    Serial.println();
    Serial.println("Saved backups:");

    bool found = false;
    for (File file = root.openNextFile(); file; file = root.openNextFile()) {
        char profileName[Storage::PROFILE_NAME_MAX + 1];
        if (!extractProfileName(file.name(), profileName, sizeof(profileName))) {
            continue;
        }
        found = true;
        Serial.printf("  %s (%lu bytes)\n", profileName, static_cast<unsigned long>(file.size()));
    }

    if (!found) {
        Serial.println("  none");
    }

    Serial.println();
}

DeviceId parseDevice(const char *token) {
    if (tokenEquals(token, "pumpa") || tokenEquals(token, "pump1") || tokenEquals(token, "feed")) {
        return DeviceId::PumpA;
    }
    if (tokenEquals(token, "pumpb") || tokenEquals(token, "pump2") || tokenEquals(token, "transfer")) {
        return DeviceId::PumpB;
    }
    if (tokenEquals(token, "intake") || tokenEquals(token, "valve1")) {
        return DeviceId::IntakeValve;
    }
    if (tokenEquals(token, "bypass") || tokenEquals(token, "valve2")) {
        return DeviceId::BypassValve;
    }
    if (tokenEquals(token, "conveyor") || tokenEquals(token, "belt")) {
        return DeviceId::Conveyor;
    }
    if (tokenEquals(token, "heater") || tokenEquals(token, "oven")) {
        return DeviceId::Heater;
    }
    return DeviceId::Unknown;
}

void printPrompt() {
    Serial.print("panel> ");
}

void printHelp() {
    Serial.println();
    Serial.println("Commands:");
    Serial.println("  help");
    Serial.println("  status");
    Serial.println("  start <pumpa|pumpb|conveyor|heater>");
    Serial.println("  stop <pumpa|pumpb|conveyor|heater>");
    Serial.println("  open <intake|bypass>");
    Serial.println("  close <intake|bypass>");
    Serial.println("  speed <0-100>");
    Serial.println("  target <40-220>");
    Serial.println("  preset <idle|fill|process|transfer>");
    Serial.println("  save [name]");
    Serial.println("  load [name]  (preview + confirm)");
    Serial.println("  backups");
    Serial.println("  alarm ack");
    Serial.println("  shutdown");
    Serial.println();
}

void printStatus() {
    drawDashboard();
}

const char *statusColor(bool active, const char *activeColor) {
    return active ? activeColor : SerialUi::GRAY;
}

const char *backupColor() {
    if (!fileSystemReady || tokenEquals(backupLabel, Storage::DEFAULT_STATUS)) {
        return SerialUi::GRAY;
    }
    if (tokenEquals(backupLabel, Storage::DIRTY_STATUS)) {
        return SerialUi::YELLOW;
    }
    return SerialUi::GREEN;
}

void printDivider(char ch) {
    for (int i = 0; i < 79; ++i) {
        Serial.print(ch);
    }
    Serial.println();
}

void renderStateRow(const char *label, const char *state, const char *color, const char *detail) {
    Serial.printf(" %-16s ", label);
    Serial.print(color);
    Serial.print(state);
    Serial.print(SerialUi::RESET);
    Serial.printf("  %s\n", detail);
}

void renderBar(const char *label, float value, float maxValue, size_t width, const char *color, const char *suffix) {
    const float safeValue = clampf(value, 0.0f, maxValue);
    const size_t filled = static_cast<size_t>((safeValue / maxValue) * width);

    Serial.printf(" %-8s [", label);
    Serial.print(color);
    for (size_t i = 0; i < filled; ++i) {
        Serial.print('#');
    }
    Serial.print(SerialUi::RESET);
    for (size_t i = filled; i < width; ++i) {
        Serial.print('-');
    }
    Serial.printf("] %3.0f%s\n", safeValue, suffix);
}

void drawDashboard() {
    char uptimeText[20];
    char heaterDetail[40];
    char conveyorDetail[40];

    snprintf(uptimeText, sizeof(uptimeText), "%lus", (millis() - bootMs) / 1000UL);
    snprintf(heaterDetail, sizeof(heaterDetail), "target %.0fC / %.1fbar", heater.targetC, metrics.pressureBar);
    snprintf(conveyorDetail, sizeof(conveyorDetail), "speed %u%% / flow %.0f%%", conveyor.speedPct, metrics.flowPct);

    Serial.print(SerialUi::CLEAR);
    Serial.print(SerialUi::BOLD);
    Serial.print(SerialUi::CYAN);
    Serial.print("INDUSTRIAL CONTROL PANEL");
    Serial.print(SerialUi::RESET);
    Serial.print("  mode:");
    Serial.print(SerialUi::CYAN);
    Serial.print(modeLabel);
    Serial.print(SerialUi::RESET);
    Serial.print("  uptime:");
    Serial.print(uptimeText);
    Serial.print("  backup:");
    Serial.print(backupColor());
    Serial.print(backupLabel);
    Serial.print(SerialUi::RESET);
    Serial.println();

    printDivider('=');
    renderStateRow("FEED CIRCUIT", pumpA.enabled ? "ONLINE" : "STANDBY",
            statusColor(pumpA.enabled, SerialUi::GREEN),
            intakeValve.open ? "supply path open" : "waiting on valve");
    renderStateRow("TRANSFER LINE", pumpB.enabled ? "ONLINE" : "STANDBY",
            statusColor(pumpB.enabled, SerialUi::GREEN),
            bypassValve.open ? "pressure relaxed" : "pressure loaded");
    renderStateRow("INTAKE VALVE", intakeValve.open ? "OPEN" : "CLOSED",
            statusColor(intakeValve.open, SerialUi::CYAN),
            intakeValve.open ? "tank receiving feed" : "feed isolated");
    renderStateRow("BYPASS VALVE", bypassValve.open ? "OPEN" : "CLOSED",
            statusColor(bypassValve.open, SerialUi::YELLOW),
            bypassValve.open ? "loop recirculating" : "line pressurized");
    renderStateRow("CONVEYOR", conveyor.running ? "MOVING" : "STOPPED",
            statusColor(conveyor.running, SerialUi::CYAN), conveyorDetail);
    renderStateRow("HEATER", heater.enabled ? "HEATING" : "IDLE",
            statusColor(heater.enabled, SerialUi::YELLOW), heaterDetail);
    printDivider('-');
    renderBar("LEVEL", metrics.tankLevelPct, 100.0f, 24, SerialUi::CYAN, "%");
    renderBar("FLOW", metrics.flowPct, 100.0f, 24, SerialUi::GREEN, "%");
    renderBar("TEMP", heater.currentC, 180.0f, 24, SerialUi::YELLOW, "C");
    renderBar("PRESSURE", metrics.pressureBar, 10.0f, 24,
            alarmState.active ? SerialUi::RED : SerialUi::BLUE, "b");
    printDivider('-');
    Serial.print(" ALARM    ");
    Serial.print(alarmState.active ? SerialUi::RED : SerialUi::GREEN);
    Serial.print(alarmState.active ? "ACTIVE" : "READY");
    Serial.print(SerialUi::RESET);
    Serial.print("  ");
    Serial.println(alarmState.message);
    Serial.print(" NOTICE   ");
    Serial.print(SerialUi::WHITE);
    Serial.print(noticeLine);
    Serial.print(SerialUi::RESET);
    Serial.println();
    printDivider('=');
    Serial.print(SerialUi::DIM);
    Serial.println(" Commands: help status start stop open close speed target preset save load backups alarm ack shutdown");
    Serial.print(SerialUi::RESET);
    Serial.print("panel> ");
}

void evaluateAlarmConditions() {
    alarmState.active = false;
    setAlarmMessage("SYSTEM NOMINAL");

    if (heater.enabled && metrics.tankLevelPct < 5.0f) {
        alarmState.active = true;
        setAlarmMessage("DRY HEATER");
        return;
    }

    if (metrics.pressureBar > 8.0f) {
        alarmState.active = true;
        setAlarmMessage("HIGH PRESSURE");
        return;
    }

    if (heater.currentC > heater.targetC + 28.0f) {
        alarmState.active = true;
        setAlarmMessage("OVER TEMP");
        return;
    }

    if (pumpB.enabled && metrics.tankLevelPct < 8.0f) {
        alarmState.active = true;
        setAlarmMessage("LOW TANK");
        return;
    }

    if (pumpA.enabled && !intakeValve.open) {
        alarmState.active = true;
        setAlarmMessage("FEED STARVED");
    }
}

bool applyPreset(const char *preset) {
    if (tokenEquals(preset, "idle")) {
        pumpA.enabled = false;
        pumpB.enabled = false;
        intakeValve.open = false;
        bypassValve.open = true;
        conveyor.running = false;
        heater.enabled = false;
        conveyor.speedPct = 0;
        heater.targetC = 90.0f;
        setMode("IDLE");
        return true;
    }

    if (tokenEquals(preset, "fill")) {
        pumpA.enabled = true;
        pumpB.enabled = false;
        intakeValve.open = true;
        bypassValve.open = true;
        conveyor.running = false;
        conveyor.speedPct = 0;
        heater.enabled = false;
        heater.targetC = 95.0f;
        setMode("FILL");
        return true;
    }

    if (tokenEquals(preset, "process")) {
        pumpA.enabled = true;
        pumpB.enabled = true;
        intakeValve.open = true;
        bypassValve.open = false;
        conveyor.running = true;
        conveyor.speedPct = 58;
        heater.enabled = true;
        heater.targetC = 118.0f;
        setMode("PROCESS");
        return true;
    }

    if (tokenEquals(preset, "transfer")) {
        pumpA.enabled = false;
        pumpB.enabled = true;
        intakeValve.open = false;
        bypassValve.open = true;
        conveyor.running = true;
        conveyor.speedPct = 82;
        heater.enabled = false;
        heater.targetC = 95.0f;
        setMode("TRANSFER");
        return true;
    }

    return false;
}

void handleStartStop(DeviceId device, bool enable) {
    switch (device) {
        case DeviceId::PumpA:
            pumpA.enabled = enable;
            noteManualChange();
            setNoticef("Pump A %s.", enable ? "started" : "stopped");
            return;
        case DeviceId::PumpB:
            pumpB.enabled = enable;
            noteManualChange();
            setNoticef("Pump B %s.", enable ? "started" : "stopped");
            return;
        case DeviceId::Conveyor:
            conveyor.running = enable;
            if (!enable && conveyor.speedPct == 0) {
                conveyor.speedPct = 45;
            }
            noteManualChange();
            setNoticef("Conveyor %s.", enable ? "started" : "stopped");
            return;
        case DeviceId::Heater:
            heater.enabled = enable;
            noteManualChange();
            setNoticef("Heater %s.", enable ? "enabled" : "disabled");
            return;
        default:
            setNoticef("That device uses open/close or is unknown.");
            return;
    }
}

void handleValve(DeviceId device, bool open) {
    switch (device) {
        case DeviceId::IntakeValve:
            intakeValve.open = open;
            noteManualChange();
            setNoticef("Intake valve %s.", open ? "opened" : "closed");
            return;
        case DeviceId::BypassValve:
            bypassValve.open = open;
            noteManualChange();
            setNoticef("Bypass valve %s.", open ? "opened" : "closed");
            return;
        default:
            setNoticef("Only intake and bypass are valve targets.");
            return;
    }
}

size_t readSerialLine(char *buffer, size_t bufferSize) {
    size_t length = 0;

    if (bufferSize == 0) {
        return 0;
    }

    while (true) {
        while (!Serial.available()) {
            delay(1);
        }

        const int incoming = Serial.read();
        if (incoming < 0) {
            continue;
        }

        if (incoming == '\r') {
            continue;
        }

        if (incoming == '\n') {
            break;
        }

        if (length < bufferSize - 1) {
            buffer[length++] = static_cast<char>(incoming);
        }
    }

    buffer[length] = '\0';
    return length;
}

void executeShutdown() {
    pumpA.enabled = false;
    pumpB.enabled = false;
    intakeValve.open = false;
    bypassValve.open = false;
    conveyor.running = false;
    heater.enabled = false;
    conveyor.speedPct = 0;
    setMode("SHUTDOWN");
    setNoticef("Shutdown complete.");
    drawDashboard();
}

void shutdownPrompt() {
    char user[32];
    char pass[32];
    char retry[8];

    while (true) {
        Serial.println("Admin permissions are required for shutting down the systems.");
        Serial.print("Username: ");
        readSerialLine(user, BUFFER_SIZE);

        Serial.print("Password: ");
        readSerialLine(pass, BUFFER_SIZE);

        if (strcmp(user, "admin") == 0 && strcmp(pass, "sup3rl33tp4ssw0rd") == 0) {
            Serial.println("shutting down all systems...");
            executeShutdown();
            return;
        }

        Serial.print("Wrong username or password. Try again? [y/N]: ");
        readSerialLine(retry, sizeof(retry));

        if (tokenEquals(retry, "y") || tokenEquals(retry, "yes")) {
            continue;
        }

        if (retry[0] != '\0' && !tokenEquals(retry, "n") && !tokenEquals(retry, "no")) {
            Serial.println("Please answer 'yes' or 'no'.");
        }

        setNoticef("Shutdown canceled.");
        drawDashboard();
        return;
    }
}

void processCommand(char *line) {
    char *argv[4] = {nullptr, nullptr, nullptr, nullptr};
    int argc = 0;
    char *save = nullptr;

    for (char *token = strtok_r(line, " \t", &save); token != nullptr && argc < 4;
            token = strtok_r(nullptr, " \t", &save)) {
        argv[argc++] = token;
    }

    if (argc == 0) {
        printPrompt();
        return;
    }

    if (tokenEquals(argv[0], "shutdown")) {
        shutdownPrompt();
        return;
    }

    if (tokenEquals(argv[0], "help")) {
        printHelp();
        printPrompt();
        return;
    }

    if (tokenEquals(argv[0], "status")) {
        printStatus();
        return;
    }

    if (tokenEquals(argv[0], "start") || tokenEquals(argv[0], "stop")) {
        if (argc < 2) {
            setNoticef("Usage: start|stop <pumpa|pumpb|conveyor|heater>");
            drawDashboard();
            return;
        }
        handleStartStop(parseDevice(argv[1]), tokenEquals(argv[0], "start"));
        drawDashboard();
        return;
    }

    if (tokenEquals(argv[0], "open") || tokenEquals(argv[0], "close")) {
        if (argc < 2) {
            setNoticef("Usage: open|close <intake|bypass>");
            drawDashboard();
            return;
        }
        handleValve(parseDevice(argv[1]), tokenEquals(argv[0], "open"));
        drawDashboard();
        return;
    }

    if (tokenEquals(argv[0], "speed")) {
        if (argc < 2) {
            setNoticef("Usage: speed <0-100>");
            drawDashboard();
            return;
        }
        int speed = atoi(argv[1]);
        conveyor.speedPct = static_cast<uint8_t>(clampf(speed, 0, 100));
        conveyor.running = conveyor.speedPct > 0;
        noteManualChange();
        setNoticef("Conveyor speed set to %u%%.", conveyor.speedPct);
        drawDashboard();
        return;
    }

    if (tokenEquals(argv[0], "target")) {
        if (argc < 2) {
            setNoticef("Usage: target <40-220>");
            drawDashboard();
            return;
        }
        heater.targetC = clampf(static_cast<float>(atof(argv[1])), 40.0f, 220.0f);
        noteManualChange();
        setNoticef("Heater target set to %.0f C.", heater.targetC);
        drawDashboard();
        return;
    }

    if (tokenEquals(argv[0], "preset")) {
        if (argc < 2) {
            setNoticef("Usage: preset <idle|fill|process|transfer|shutdown>");
            drawDashboard();
            return;
        }
        if (!applyPreset(argv[1])) {
            setNoticef("Unknown preset. Use idle, fill, process, transfer, or shutdown.");
            drawDashboard();
            return;
        }
        markConfigDirty();
        setNoticef("Preset applied: %s.", modeLabel);
        drawDashboard();
        return;
    }

    if (tokenEquals(argv[0], "save")) {
        saveConfiguration(argc >= 2 ? argv[1] : nullptr);
        drawDashboard();
        return;
    }

    if (tokenEquals(argv[0], "load")) {
        loadConfiguration(argc >= 2 ? argv[1] : nullptr);
        return;
    }

    if (tokenEquals(argv[0], "backups") || tokenEquals(argv[0], "files")) {
        listConfigurations();
        printPrompt();
        return;
    }

    if (tokenEquals(argv[0], "alarm") && argc >= 2 && tokenStarts(argv[1], "ack")) {
        if (alarmState.active) {
            setNoticef("Alarm acknowledged. Cause still active: %s.", alarmState.message);
        } else {
            setNoticef("No active alarm.");
        }
        drawDashboard();
        return;
    }

    setNoticef("Unknown command. Type 'help' for the command list.");
    drawDashboard();
}

void handleSerial() {
    while (Serial.available() > 0) {
        const int incoming = Serial.read();
        if (incoming < 0) {
            return;
        }

        if (incoming == '\r') {
            continue;
        }

        if (incoming == '\n') {
            Serial.println();
            inputBuffer[inputLength] = '\0';
            if (pendingLoadConfirmation) {
                handleLoadConfirmation(inputBuffer);
            } else {
                processCommand(inputBuffer);
            }
            inputLength = 0;
            continue;
        }

        if ((incoming == 8 || incoming == 127) && inputLength > 0) {
            --inputLength;
            Serial.print("\b \b");
            continue;
        }

        if (isPrintable(incoming) && inputLength < sizeof(inputBuffer) - 1) {
            inputBuffer[inputLength++] = static_cast<char>(incoming);
            Serial.write(static_cast<char>(incoming));
        }
    }
}

void updatePlantModel(float dt) {
    const float fillDrive = (intakeValve.open ? 18.0f : 0.0f) + (pumpA.enabled ? 11.0f : 0.0f);
    const float drawDrive = (pumpB.enabled ? 15.0f : 0.0f) + (conveyor.running ? conveyor.speedPct * 0.11f : 0.0f);
    const float levelDelta = (fillDrive - drawDrive) * 0.055f * dt;
    const float pressureTarget =
        0.8f +
        (pumpA.enabled ? (intakeValve.open ? 1.7f : 3.4f) : 0.0f) +
        (pumpB.enabled ? (bypassValve.open ? 1.2f : 2.6f) : 0.0f) +
        (conveyor.running ? conveyor.speedPct * 0.02f : 0.0f) -
        (bypassValve.open ? 0.9f : 0.0f);
    const float flowTarget =
        (pumpA.enabled ? 28.0f : 0.0f) +
        (pumpB.enabled ? 32.0f : 0.0f) +
        (conveyor.running ? conveyor.speedPct * 0.55f : 0.0f);
    float heatTarget = 24.0f;

    metrics.tankLevelPct = clampf(metrics.tankLevelPct + levelDelta, 0.0f, 100.0f);
    metrics.pressureBar += (pressureTarget - metrics.pressureBar) * clampf(dt * 2.6f, 0.0f, 1.0f);
    metrics.flowPct += (flowTarget - metrics.flowPct) * clampf(dt * 2.8f, 0.0f, 1.0f);

    if (heater.enabled && metrics.tankLevelPct > 2.0f) {
        heatTarget = heater.targetC;
    } else if (pumpA.enabled || pumpB.enabled) {
        heatTarget = 31.0f;
    }

    heater.currentC += (heatTarget - heater.currentC) * clampf(dt * 0.5f, 0.0f, 1.0f);

    if (!heater.enabled && heater.currentC > 28.0f && conveyor.running) {
        heater.currentC -= 0.18f * dt * conveyor.speedPct / 20.0f;
    }

    metrics.flowPct = clampf(metrics.flowPct, 0.0f, 100.0f);
    metrics.pressureBar = clampf(metrics.pressureBar, 0.0f, 10.0f);
    heater.currentC = clampf(heater.currentC, 18.0f, 240.0f);

    evaluateAlarmConditions();
}

void drawSplash() {
    Serial.print(SerialUi::CLEAR);
    printDivider('=');
    Serial.print(SerialUi::BOLD);
    Serial.print(SerialUi::CYAN);
    Serial.println(" INDUSTRIAL PANEL");
    Serial.print(SerialUi::RESET);
    Serial.println(" Serial dashboard mode");
    Serial.println(" Management-friendly ANSI console :ppp");
    printDivider('=');
    delay(900);
}

void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 1500) {
    }

    fileSystemReady = SPIFFS.begin(true);

    bootMs = millis();
    setNoticef("Storage: %s. Type 'help' for available commands.",
            fileSystemReady ? "SPIFFS READY" : "OFFLINE");
    drawSplash();
    drawDashboard();
}

void loop() {
    const unsigned long now = millis();
    const bool firstModelTick = lastModelMs == 0;

    handleSerial();

    if (firstModelTick || now - lastModelMs >= 100) {
        const float dt = firstModelTick ? 0.1f : (now - lastModelMs) / 1000.0f;
        lastModelMs = now;
        updatePlantModel(dt);
    }
}
