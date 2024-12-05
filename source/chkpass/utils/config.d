module chkpass.utils.config;

import std.file;
import readconf;
import singlog;

struct Settings {
    string check = "login";
    string change = "passwd";
}

Settings readConfigFile(string configFile) {
    Settings settings;

    if (configFile.exists) {
        rc.read(configFile);

        ConfigSection mainSection;
        
        try {
            mainSection = rc[][];
            if (!mainSection.key("check").empty) settings.check = mainSection.key("check");
            if (!mainSection.key("change").empty) settings.change = mainSection.key("change");
        } catch (Exception e) {
            log.w("An error occurred while reading the configuration file");
        }
    }

    return settings;
}
