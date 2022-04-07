![Logpresso Logo](logo.png)

log4j2-scan is a single binary command-line tool for CVE-2021-44228 vulnerability scanning and mitigation patch. It also supports nested JAR file scanning and patch. It also detects CVE-2021-45046 (log4j 2.15.0), CVE-2021-45105 (log4j 2.16.0), CVE-2021-44832 (log4j 2.17.0), CVE-2021-4104, CVE-2019-17571, CVE-2017-5645, CVE-2020-9488, CVE-2022-23302, CVE-2022-23305, CVE-2022-23307 (log4j 1.x), and CVE-2021-42550 (logback 0.9-1.2.7) vulnerabilities.

### Log4j Risk Management
You can integrate log4j2-scan with [Logpresso Watch](https://logpresso.watch) service for reporting and patch management. Visit https://logpresso.watch for details.

### Download
* [log4j2-scan 3.0.1 (Windows x64, 7z)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v3.0.1/logpresso-log4j2-scan-3.0.1-win64.7z)
* [log4j2-scan 3.0.1 (Windows x64, zip)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v3.0.1/logpresso-log4j2-scan-3.0.1-win64.zip)
  * If you get `VCRUNTIME140.dll not found` error, install [Visual C++ Redistributable](https://docs.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170).
  * If native executable doesn't work, use the JAR instead. 32bit is not supported.  
  * 7zip is available from www.7zip.org, and is open source and free.
* [log4j2-scan 3.0.1 (Linux x64)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v3.0.1/logpresso-log4j2-scan-3.0.1-linux.tar.gz)
* [log4j2-scan 3.0.1 (Linux aarch64)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v3.0.1/logpresso-log4j2-scan-3.0.1-linux-aarch64.tar.gz)
  * If native executable doesn't work, use the JAR instead. 32bit is not supported.
* [log4j2-scan 3.0.1 (Mac OS)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v3.0.1/logpresso-log4j2-scan-3.0.1-darwin.zip)
* [log4j2-scan 3.0.1 (Any OS, 620KB)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v3.0.1/logpresso-log4j2-scan-3.0.1.jar)

### Build
* [How to build Native Image](https://github.com/logpresso/CVE-2021-44228-Scanner/wiki/FAQ#how-to-build-native-image)

### How to use
Just run log4j2-scan.exe or log4j2-scan with target directory path. The logpresso-log4j2-scan.jar should work with JRE/JDK 7+

`--fix` option is supported for following vulnerabilities:
* Log4j v2
  * CVE-2021-44228 (JndiLookup)
  * CVE-2021-45046 (JndiLookup)
* Log4j v1
  * CVE-2021-4104 (JMSAppender)
  * CVE-2019-17571 (SocketServer)
  * CVE-2020-9488 (SMTPAppender)
  * CVE-2022-23302 (JMSSink)
  * CVE-2022-23305 (JDBCAppender)
  * CVE-2022-23307 (chainsaw package)

`--fix` option doesn't mitigate following vulnerabilities:
* Log4j v2
  * CVE-2021-44832 (JDBCAppender)
  * CVE-2021-45105 (DoS)
  * CVE-2017-5645 (SocketServer)
  * CVE-2020-9488 (SMTPAppender)
* Logback
  * CVE-2021-42550

Usage
```
Logpresso CVE-2021-44228 Vulnerability Scanner 3.0.1 (2022-02-13)
Usage: log4j2-scan [--scan-log4j1] [--fix] target_path1 target_path2

-f [config_file_path]
        Specify config file path which contains scan target paths.
        Paths should be separated by new line. Prepend # for comment.
--scan-log4j1
        Enables scanning for log4j 1 versions.
--scan-logback
        Enables scanning for logback CVE-2021-42550.
--scan-zip
        Scan also .zip extension files. This option may slow down scanning.
--zip-charset
        Specify an alternate zip encoding other than utf-8. System default charset is used if not specified.
--fix
        Backup original file and remove JndiLookup.class from JAR recursively.
        With --scan-log4j1 option, it also removes JMSAppender.class, SocketServer.class, SMTPAppender.class, SMTPAppender$1.class,
        JMSSink.class, JDBCAppender.class, and all classes of org.apache.log4j.chainsaw package
--force-fix
        Do not prompt confirmation. Don't use this option unless you know what you are doing.
--restore [backup_file_path]
        Unfix JAR files using zip archived file.
--backup-path [zip_output_path]
        Specify backup file path.
--backup-ext [zip]
        Specify backup file extension. zip by default.
        If --backup-path is specified, this option is ignored.
--all-drives
        Scan all drives on Windows
--drives c,d
        Scan specified drives on Windows. Spaces are not allowed here.
--no-symlink
        Do not detect symlink as vulnerable file.
--exclude [path_prefix]
        Path prefixes of directories whose absolute path starts with the specified value will be excluded.
        Does not support relative paths. You can specify multiple --exclude [path_prefix] pairs
--exclude-config [config_file_path]
        Specify exclude path prefix list in text file. Paths should be separated by new line. Prepend # for comment.
--exclude-pattern [pattern]
        Exclude specified paths of directories by pattern. Supports fragments.
        You can specify multiple --exclude-pattern [pattern] pairs (non regex)
--exclude-file-config [config_file_path]
        Specify exclude file path list in text file. Paths should be separated by new line. Prepend # for comment.
--exclude-fs nfs,tmpfs
        Exclude paths by file system type. nfs, nfs3, nfs4, afs, cifs, autofs,
        tmpfs, devtmpfs, fuse.sshfs, smbfs and iso9660 is ignored by default.
--api-key [key]
        Send reports to Logpresso Watch service.
--http-proxy [addr:port]
        Send reports via specified HTTP proxy server.
--syslog-udp [host:port]
        Send reports to remote syslog host.
        Send vulnerable, potentially vulnerable, and mitigated reports by default.
--syslog-level [level]
        Send reports only if report is higher or equal to specified level.
        Specify alert for vulnerable and potentially vulnerable reports.
        Specify info for vulnerable, potentially vulnerable, and mitigated reports.
        Specify debug for vulnerable, potentially vulnerable, mitigated, and error reports.
--syslog-facility [code]
        Default value is 16 (LOCAL0). Facility value must be in the range of 0 to 23 inclusive.
--rfc5424
        Follow RFC5424 The Syslog Protocol strictly.
--report-csv
        Generate log4j2_scan_report_yyyyMMdd_HHmmss.csv in working directory if not specified otherwise via --report-path [path]
--report-json
        Generate log4j2_scan_report_yyyyMMdd_HHmmss.json in working directory if not specified otherwise via --report-path [path]
--report-patch
        Report also patched log4j file.
--report-path
        Specify report output path including filename. Implies --report-csv.
--report-dir
        Specify report output directory. Implies --report-csv.
--no-empty-report
        Do not generate empty report.
--csv-log-path
        Specify csv log file path. If log file exists, log will be appended.
--json-log-path
        Specify json log file path. If log file exists, log will be appended.
--old-exit-code
        Return sum of vulnerable and potentially vulnerable files as exit code.
--debug
        Print exception stacktrace for debugging.
--trace
        Print all directories and files while scanning.
--silent
        Do not print progress message.
--throttle
        Limit scan files per second.
--help
        Print this help.
```

On Windows
```
log4j2-scan [--fix] target_path
```
On Linux
```
./log4j2-scan [--fix] target_path
```
On UNIX (AIX, Solaris, and so on)
```
java -jar logpresso-log4j2-scan-3.0.1.jar [--fix] target_path
```

If you add `--fix` option, this program will copy vulnerable original JAR file to .bak file, and create new JAR file without `org/apache/logging/log4j/core/lookup/JndiLookup.class` entry. All .bak files are archived into the single zip file which is named by `log4j2_scan_backup_yyyyMMdd_HHmmss.zip`, then deleted safely. In most environments, JNDI lookup feature will not be used. However, you must use this option at your own risk. You can easily restore original vulnerable JAR files using `--restore` option.

Depending the Operating System:

- Windows: It is necessary to shutdown any running JVM process before applying patch due to lock files. Start affected JVM process after fix.
- Linux/macOS: Apply patch, restart the JVM after

If you want to automate patch job, use `--force-fix` option. With this option, this program will no longer prompt for confirmation.

`(mitigated)` tag will be displayed if `org/apache/logging/log4j/core/lookup/JndiLookup.class` entry is removed from JAR file.

If you add `--trace` option, this program will print all visited directories and files. Use this option only for debugging.

On Windows:
```
CMD> log4j2-scan.exe D:\tmp
[*] Found CVE-2021-44228 vulnerability in D:\tmp\elasticsearch-7.16.0\bin\elasticsearch-sql-cli-7.16.0.jar, log4j 2.11.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\elasticsearch-7.16.0\lib\log4j-core-2.11.1.jar, log4j 2.11.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\flink-1.14.0\lib\log4j-core-2.14.1.jar, log4j 2.14.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\logstash-7.16.0\logstash-core\lib\jars\log4j-core-2.14.0.jar, log4j 2.14.0
[*] Found CVE-2021-44228 vulnerability in D:\tmp\logstash-7.16.0\vendor\bundle\jruby\2.5.0\gems\logstash-input-tcp-6.2.1-java\vendor\jar-dependencies\org\logstash\inputs\logstash-input-tcp\6.2.1\logstash-input-tcp-6.2.1.jar, log4j 2.9.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-7.7.3\solr-7.7.3\contrib\prometheus-exporter\lib\log4j-core-2.11.0.jar, log4j 2.11.0
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-7.7.3\solr-7.7.3\server\lib\ext\log4j-core-2.11.0.jar, log4j 2.11.0
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-8.11.0\contrib\prometheus-exporter\lib\log4j-core-2.14.1.jar, log4j 2.14.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-8.11.0\server\lib\ext\log4j-core-2.14.1.jar, log4j 2.14.1

Scanned 5047 directories and 26251 files
Found 9 vulnerable files
Completed in 0.42 seconds
```

### How it works
Run in 5 steps:
1. Find all .jar, .war, .ear, .aar, .rar, .nar files recursively.
2. Find `META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties` entry from JAR file.
3. Read groupId, artifactId, and version.
4. Compare log4j2 version and print vulnerable version.
5. If --fix option is used, backup vulnerable file and patch it.
   * For example, original vulnerable.jar is copied to vulnerable.jar.bak
6. Archive all backup files into the zip file `log4j2_scan_backup_yyyyMMdd_HHmmss.zip`, then delete .bak files.   

### Exit code for automation
* -1 failed to run
* 0 for clean (No vulnerability)
* 1 for found
* 2 for some errors

### Tool Integrations
* [HCL BigFix](https://forum.bigfix.com/t/log4j-cve-2021-44228-cve-2021-45046-summary-page)
* [Checkmk](https://checkmk.com/blog/automatically-detecting-log4j-vulnerabilities-in-your-it)
  * See also [checkmk CVE-log4j agent plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin)

### Contact
If you have any question or issue, create an issue in this repository.

### About Logpresso
Logpresso is a leading company in the AI and big data industry located in South Korea.
Logpresso provides SIEM, SOAR, Log management, and FDS solutions with its own big data platform.
