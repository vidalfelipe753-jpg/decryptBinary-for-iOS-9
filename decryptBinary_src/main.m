#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <spawn.h>

// libproc declarations (not available in iOS SDK headers)
#define PROC_PIDPATHINFO_MAXSIZE (4 * 1024)
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

extern char **environ;

// Get bundle ID from Info.plist in app bundle
static NSString* getBundleIDFromPath(NSString *appPath) {
    // Extract .app bundle path
    NSRange appRange = [appPath rangeOfString:@".app/"];
    if (appRange.location == NSNotFound) {
        appRange = [appPath rangeOfString:@".app"];
        if (appRange.location == NSNotFound) {
            return nil;
        }
    }

    NSString *bundlePath = [appPath substringToIndex:appRange.location + appRange.length];
    NSString *infoPlistPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];

    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
    if (infoPlist) {
        return infoPlist[@"CFBundleIdentifier"];
    }

    return nil;
}

// Get all running processes
static NSArray* getRunningProcesses() {
    NSMutableArray *processes = [NSMutableArray array];

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size;

    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) {
        return processes;
    }

    struct kinfo_proc *procs = malloc(size);
    if (sysctl(mib, 4, procs, &size, NULL, 0) < 0) {
        free(procs);
        return processes;
    }

    int count = size / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];

        if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
            if (strstr(pathbuf, ".app/")) {
                NSMutableDictionary *info = [NSMutableDictionary dictionary];
                info[@"pid"] = @(pid);
                info[@"path"] = [NSString stringWithUTF8String:pathbuf];

                // Extract app name from path
                NSString *path = info[@"path"];
                NSArray *components = [path componentsSeparatedByString:@"/"];
                for (NSString *comp in components) {
                    if ([comp hasSuffix:@".app"]) {
                        NSString *appName = [comp stringByReplacingOccurrencesOfString:@".app" withString:@""];
                        info[@"name"] = appName;
                        break;
                    }
                }

                // Get bundle ID from Info.plist
                NSString *bundleID = getBundleIDFromPath(path);
                if (bundleID) {
                    info[@"bundleID"] = bundleID;
                }

                [processes addObject:info];
            }
        }
    }

    free(procs);
    return processes;
}

// Private API interfaces
@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
@property (readonly, nonatomic) NSURL *dataContainerURL;
@property (readonly, nonatomic) NSURL *bundleURL;
@property (readonly, nonatomic) NSString *localizedName;
@property (readonly, nonatomic) NSString *bundleExecutable;
@end

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (BOOL)openApplicationWithBundleID:(NSString *)bundleID;
@end

// Check if running in rootless environment
static BOOL isRootlessEnvironment(void) {
    // Check if /var/jb exists (rootless jailbreak marker)
    struct stat st;
    return (stat("/var/jb", &st) == 0 && S_ISDIR(st.st_mode));
}

// Get shell path based on environment
static const char* getShellPath(void) {
    return isRootlessEnvironment() ? "/var/jb/bin/sh" : "/bin/sh";
}

// Load MobileCoreServices framework and return handle
static void* loadMobileCoreServices(void) {
    void *handle = dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY);
    if (!handle) {
        printf("[!] Error: Cannot load MobileCoreServices framework\n");
    }
    return handle;
}

// Launch app by bundle ID using LSApplicationWorkspace
static BOOL launchAppByBundleID(NSString *bundleID) {
    @try {
        void *handle = loadMobileCoreServices();
        if (!handle) {
            return NO;
        }

        // Get LSApplicationWorkspace class
        Class LSApplicationWorkspaceClass = NSClassFromString(@"LSApplicationWorkspace");
        if (!LSApplicationWorkspaceClass) {
            printf("[!] Error: Cannot find LSApplicationWorkspace class\n");
            dlclose(handle);
            return NO;
        }

        // Get default workspace
        id workspace = [LSApplicationWorkspaceClass defaultWorkspace];
        if (!workspace) {
            printf("[!] Error: Cannot get default workspace\n");
            dlclose(handle);
            return NO;
        }

        // Open application with bundle ID
        BOOL result = NO;
        if ([workspace respondsToSelector:@selector(openApplicationWithBundleID:)]) {
            result = [workspace openApplicationWithBundleID:bundleID];
        }

        dlclose(handle);

        if (result) {
            // Give the app time to launch
            sleep(2);
        }

        return result;
    }
    @catch (NSException *exception) {
        printf("[!] Exception: %s\n", [[exception description] UTF8String]);
        return NO;
    }
}

// List all running apps
static void listApps() {
    NSArray *processes = getRunningProcesses();

    printf("%-8s %-25s %-40s %s\n", "PID", "Name", "Bundle ID", "Path");
    printf("----------------------------------------------------------------------------------------------------\n");

    for (NSDictionary *proc in processes) {
        printf("%-8d %-25s %-40s %s\n",
               [proc[@"pid"] intValue],
               [proc[@"name"] UTF8String] ?: "unknown",
               [proc[@"bundleID"] UTF8String] ?: "N/A",
               [proc[@"path"] UTF8String]);
    }

    printf("\n");
}

// Create IPA from decrypted binary
static BOOL createIPA(NSString *bundlePath, NSString *decryptedBinaryPath, NSString *executableName, NSString *outputDir, NSString *appName) {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error = nil;

    // Create temporary Payload directory
    NSString *tempDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSString *payloadDir = [tempDir stringByAppendingPathComponent:@"Payload"];

    if (![fileManager createDirectoryAtPath:payloadDir withIntermediateDirectories:YES attributes:nil error:&error]) {
        printf("[!] Error: Cannot create Payload directory: %s\n", [[error localizedDescription] UTF8String]);
        return NO;
    }

    // Copy .app bundle to Payload directory
    NSString *appBundleName = [bundlePath lastPathComponent];
    NSString *destAppPath = [payloadDir stringByAppendingPathComponent:appBundleName];

    printf("[*] Copying app bundle to temporary directory...\n");
    if (![fileManager copyItemAtPath:bundlePath toPath:destAppPath error:&error]) {
        printf("[!] Error: Cannot copy app bundle: %s\n", [[error localizedDescription] UTF8String]);
        [fileManager removeItemAtPath:tempDir error:nil];
        return NO;
    }

    // Replace original binary with decrypted one
    NSString *originalBinaryPath = [destAppPath stringByAppendingPathComponent:executableName];

    printf("[*] Replacing binary with decrypted version...\n");
    if ([fileManager fileExistsAtPath:originalBinaryPath]) {
        if (![fileManager removeItemAtPath:originalBinaryPath error:&error]) {
            printf("[!] Error: Cannot remove original binary: %s\n", [[error localizedDescription] UTF8String]);
            [fileManager removeItemAtPath:tempDir error:nil];
            return NO;
        }
    }

    if (![fileManager copyItemAtPath:decryptedBinaryPath toPath:originalBinaryPath error:&error]) {
        printf("[!] Error: Cannot copy decrypted binary: %s\n", [[error localizedDescription] UTF8String]);
        [fileManager removeItemAtPath:tempDir error:nil];
        return NO;
    }

    // Set executable permissions
    NSDictionary *attrs = @{NSFilePosixPermissions: @0755};
    if (![fileManager setAttributes:attrs ofItemAtPath:originalBinaryPath error:&error]) {
        printf("[!] Warning: Cannot set executable permissions: %s\n", [[error localizedDescription] UTF8String]);
    }

    // Create IPA (zip file)
    NSString *ipaPath = [NSString stringWithFormat:@"%@/%@.ipa", outputDir, appName];

    printf("[*] Creating IPA archive...\n");

    // Use zip command to create IPA (IPA is just a zip file)
    // We need to cd into tempDir first, then zip the Payload folder
    BOOL rootless = isRootlessEnvironment();
    const char *shellPath = getShellPath();
    const char *zipPath = rootless ? "/var/jb/usr/bin/zip" : "/usr/bin/zip";

    printf("[*] Environment: %s\n", rootless ? "Rootless" : "Rootful");

    pid_t pid;
    const char *args[] = {
        shellPath,
        "-c",
        [[NSString stringWithFormat:@"cd '%@' && '%s' -qr '%@' Payload",
          tempDir, zipPath, ipaPath] UTF8String],
        NULL
    };

    if (posix_spawn(&pid, shellPath, NULL, NULL, (char *const *)args, environ) == 0) {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("[+] IPA created successfully: %s\n", [ipaPath UTF8String]);

            // Clean up temporary directory
            [fileManager removeItemAtPath:tempDir error:nil];
            return YES;
        } else {
            printf("[!] Error: zip command failed with status %d\n", WEXITSTATUS(status));
        }
    } else {
        printf("[!] Error: Cannot spawn zip process\n");
    }

    // Clean up temporary directory
    [fileManager removeItemAtPath:tempDir error:nil];
    return NO;
}

// Print usage
static void printUsage() {
    printf("decryptbin - iOS App Binary Decryption Tool\n\n");
    printf("Usage:\n");
    printf("  decryptbin -l                List running apps\n");
    printf("  decryptbin -d <BundleID>   Dump binary (bundle ID)\n");
    printf("  decryptbin -i <BundleID>   Dump binary and create IPA (bundle ID)\n");
    printf("  decryptbin -h                Show this help\n\n");
    printf("Examples:\n");
    printf("  decryptbin -l\n");
    printf("  decryptbin -d com.apple.mobilesafari\n");
    printf("  decryptbin -i com.apple.mobilesafari\n");
    printf("Output:\n");
    printf("  -d: Decrypted binary will be saved to: <data_directory>/Documents/<appname>.decrypted\n");
    printf("  -i: IPA will be saved to: <data_directory>/Documents/<appname>.ipa\n\n");
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        // Check if running as root
        if (getuid() != 0) {
            printf("[!] Warning: Not running as root. Some features may not work.\n\n");
        }

        if (argc < 2) {
            printUsage();
            return 1;
        }

        NSString *option = [NSString stringWithUTF8String:argv[1]];

        if ([option isEqualToString:@"-l"] || [option isEqualToString:@"--list"]) {
            // List apps
            listApps();

        } else if ([option isEqualToString:@"-d"] || [option isEqualToString:@"--dump"] ||
                   [option isEqualToString:@"-i"] || [option isEqualToString:@"--ipa"]) {
            // Dump by identifier or create IPA
            BOOL createIPAFile = [option isEqualToString:@"-i"] || [option isEqualToString:@"--ipa"];

            if (argc < 3) {
                printf("[!] Error: Missing app identifier\n");
                printUsage();
                return 1;
            }

            NSString *bundleID = [NSString stringWithUTF8String:argv[2]];

            if (!bundleID) {
                printf("[!] Error: Cannot find bundle ID for: %s\n", argv[2]);
                printf("[*] Use -l to list running apps\n");
                return 1;
            }

            printf("[*] Target Bundle ID: %s\n", [bundleID UTF8String]);
            if (createIPAFile) {
                printf("[*] Mode: Create IPA\n");
            } else {
                printf("[*] Mode: Dump binary only\n");
            }

            // Print app information using LSApplicationProxy
            NSString *executableName = nil;
            NSString *dataDirectory = nil;
            NSString *bundlePath = nil;
            NSString *appName = nil;

            // Load MobileCoreServices framework
            void *handle = loadMobileCoreServices();
            if (!handle) {
                return 1;
            }

            // Get app information using LSApplicationProxy
            LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
            if (appProxy) {
                // Get bundle path first
                bundlePath = [[appProxy.bundleURL path] stringByStandardizingPath];
                if (!bundlePath) {
                    printf("[!] Error: Bundle path not found\n");
                    return 1;
                }

                appName = appProxy.localizedName;
                if (!appName) {
                    NSString *lastComponent = [bundlePath lastPathComponent];
                    if (lastComponent) {
                        appName = [lastComponent stringByReplacingOccurrencesOfString:@".app" withString:@""];
                    }
                }
                if (!appName) {
                    printf("[!] Error: Cannot determine app name\n");
                    return 1;
                }
                printf("[*] App Name: %s\n", [appName UTF8String]);
                printf("[*] Bundle Path: %s\n", [bundlePath UTF8String]);

                executableName = appProxy.bundleExecutable;
                if (!executableName) {
                    printf("[!] Error: Cannot determine executable name\n");
                    return 1;
                }
                printf("[*] Executable Name: %s\n", [executableName UTF8String]);

                dataDirectory = [[appProxy.dataContainerURL path] stringByStandardizingPath];
                if (!dataDirectory) {
                    printf("[!] Error: Data directory not found or inaccessible\n");
                    return 1;
                }
                printf("[*] Data Directory: %s\n", [dataDirectory UTF8String]);

            } else {
                printf("[!] Error: Could not get application proxy for %s\n", [bundleID UTF8String]);
                return 1;
            }

            // Close the framework handle
            dlclose(handle);

            // Create dynamic plist filter for MobileSubstrate
#ifdef PLIST_PATH
            NSString *plistPath = @PLIST_PATH;
#else
            NSString *plistPath = @"/Library/MobileSubstrate/DynamicLibraries/decryptBinaryDylib.plist";
#endif
            NSDictionary *filter = @{
                @"Filter": @{
                    @"Bundles": @[bundleID]
                }
            };

            if (![filter writeToFile:plistPath atomically:YES]) {
                printf("[!] Error: Cannot write plist filter file: %s\n", [plistPath UTF8String]);
                printf("[!] Permission denied. ");
                if (isRootlessEnvironment()) {
                    printf("In rootless environment, please run with sudo:\n");
                    printf("    sudo decryptbinary %s %s\n", argv[1], argv[2]);
                } else {
                    printf("Please check file permissions.\n");
                }
                return 1;
            }

            printf("[*] Filter configured for: %s\n", [bundleID UTF8String]);
            printf("[*] Reloading MobileSubstrate...\n");

            // Kill any existing app instance to reload with new filter
            pid_t killpid;
            const char *killArgs[] = {"/usr/bin/killall", "-9", [executableName UTF8String], NULL};
            posix_spawn(&killpid, "/usr/bin/killall", NULL, NULL, (char *const *)killArgs, environ);
            waitpid(killpid, NULL, 0);
            sleep(1);

            printf("[*] Launching app: %s\n", [bundleID UTF8String]);

            // Launch the app
            if (launchAppByBundleID(bundleID)) {
                printf("[+] App launched successfully\n");
                printf("[*] Waiting for binary dump...\n");

                // Wait 2 seconds for the tweak to dump the binary
                sleep(2);

                NSString *decryptedPath = [NSString stringWithFormat:@"%@/Documents/%@.decrypted",
                                          dataDirectory, executableName];

                if ([[NSFileManager defaultManager] fileExistsAtPath:decryptedPath]) {

                    // Create IPA if requested
                    if (createIPAFile) {
                        printf("\n[*] Creating IPA file...\n");
                        NSString *outputDir = [NSString stringWithFormat:@"%@/Documents", dataDirectory];
                        if (!createIPA(bundlePath, decryptedPath, executableName, outputDir, appName)) {
                            printf("[!] Error: Failed to create IPA\n");
                        }
                    } else {
                        printf("[+] Success: %s\n", [decryptedPath UTF8String]);
                    }
                } else {
                    printf("[!] Error: Failed to dump app binary\n");
                    printf("[*] Expected output: %s\n", [decryptedPath UTF8String]);
                }
            } else {
                printf("[!] Error: Failed to launch app\n");
            }

            filter = @{
                @"Filter": @{
                    @"Bundles": @[]
                }
            };

            if (![filter writeToFile:plistPath atomically:YES]) {
                printf("[!] Warning: Cannot reset plist filter file\n");
                printf("[!] The filter may remain active for the app. Run with sudo to reset properly.\n");
            }

        } else if ([option isEqualToString:@"-h"] || [option isEqualToString:@"--help"]) {
            printUsage();

        } else {
            printf("[!] Error: Unknown option: %s\n\n", argv[1]);
            printUsage();
            return 1;
        }
    }

    return 0;
}
