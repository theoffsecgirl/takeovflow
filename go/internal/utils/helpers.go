package utils

import (
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "strings"
)

var (
    RED     = "\033[0;31m"
    GREEN   = "\033[0;32m"
    YELLOW  = "\033[0;33m"
    BLUE    = "\033[0;34m"
    PURPLE  = "\033[0;35m"
    CYAN    = "\033[0;36m"
    NC      = "\033[0m"
    LOGFILE = "subdomain_scan_" + time.Now().Format("20060102_150405") + ".log"
)

func ShowBanner(version string) {
    fmt.Print(PURPLE)
    fmt.Println("▗▄▄▄▖▗▞▀▜▌█  ▄ ▗▞▀▚▖ ▗▄▖ ▄   ▄ ▗▄▄▄▖█  ▄▄▄  ▄   ▄")
    fmt.Println("  █  ▝▚▄▟▌█▄▀  ▐▛▀▀▘▐▌ ▐▌█   █ ▐▌   █ █   █ █ ▄ █")
    fmt.Println("  █       █ ▀▄ ▝▚▄▄▖▐▌ ▐▌ ▀▄▀  ▐▛▀▀▘█ ▀▄▄▄▀ █▄█▄█")
    fmt.Println("  █       █  █      ▝▚▄▞▘      ▐▌   █")
    fmt.Println("                                                  ")
    fmt.Println(CYAN + "                           by TheOffSecGirl" + NC)
    fmt.Println(BLUE + "Subdomain Takeover Scanner Pro v" + version + NC)
    fmt.Println("==================================================\n")
}

func ParseArguments(args []string) ([]string, error) {
    var domain string
    var file string
    var list string

    flag.StringVar(&domain, "d", "", "Escanea un único dominio")
    flag.StringVar(&file, "f", "", "Archivo con lista de dominios")
    flag.StringVar(&list, "l", "", "Lista de dominios separados por comas")
    flag.Parse()

    if domain != "" {
        return []string{domain}, nil
    } else if file != "" {
        content, err := ioutil.ReadFile(file)
        if err != nil {
            log.Fatal(err)
        }
        lines := strings.Split(string(content), "\n")
        return lines, nil
    } else if list != "" {
        return strings.Split(list, ","), nil
    } else {
        fmt.Println(RED + "[ERROR]" + NC + " No se especificó ningún dominio")
        fmt.Println(GREEN + "Uso:" + NC)
        fmt.Println("  subdomain_takeover_scanner -d example.com")
        fmt.Println("  subdomain_takeover_scanner -f domains.txt")
        fmt.Println("  subdomain_takeover_scanner -l \"example.com,test.com\"")
        os.Exit(1)
    }
    return nil, nil
}

func CountLines(filename string) int {
    data, _ := os.ReadFile(filename)
    return len(strings.Split(string(data), "\n"))
}

func Cleanup() {
    files, _ := filepath.Glob("*_subfinder.txt *assetfinder.txt *all.txt")
    for _, f := range files {
        os.Remove(f)
    }
}