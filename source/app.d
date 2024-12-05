import chkpass;

import commandr;
import singlog;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE;
import std.stdio : writeln;

private string programName = "chkpass";

int main(string[] args) {
    auto argumets = new Program(programName, chkpassVersion)
        .add(new Command("check", "check user password")
            .add(new Option("m", "module", "use a dedicated PAM module")
                .optional)
            .add(new Argument("username")
                .required)
            .add(new Argument("password")
                .required))
        .add(new Command("change", "change user password")
            .add(new Option("m", "module", "use a dedicated PAM module")
                .optional)
            .add(new Argument("username")
                .required)
            .add(new Argument("password")
                .required)
            .add(new Argument("new-password")
                .required))
        .parse(args);

    string pamod, user, password, newPassword, command;

    argumets
        .on("check", (a) {
            command = a.name;
            pamod = a.option("module");
            user = a.arg("username");
            password = a.arg("password");
        })
        .on("change", (a) {
            command = a.name;
            pamod = a.option("module");
            user = a.arg("username");
            password = a.arg("password");
            newPassword = a.arg("new-password");
        });

    log.output(log.output.syslog)
        .program(programName)
        .level(log.level.error);

    string configFile = "/etc/chkpass/chkpass.conf";
    auto settings = readConfigFile(configFile);

    auto auth = new Auth;

    final switch(command) {
        case "check":
            if (!pamod.length) pamod = settings.check;
            if (auth.authenticate(pamod, user, password)) {
                writeln("Password verification failed");
                return EXIT_FAILURE;
            }
            writeln("Password verification successful");
            break;
        case "change":
            if (!pamod.length) pamod = settings.change;
            if (auth.changePassword(pamod, user, password, newPassword)) {
                writeln("The password has not been changed");
                return EXIT_FAILURE;
            }
            writeln("The password was successfully changed");
            break;
    }

    return EXIT_SUCCESS;
}
