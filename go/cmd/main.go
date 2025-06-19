package scanner

import (
	"fmt"

	"github.com/tu-usuario/takeovflow/internal/scanner"
	"github.com/tu-usuario/takeovflow/internal/utils"
)

const VERSION = "3.0"

func Run(args []string) error {
    utils.ShowBanner(VERSION)

    domains, err := utils.ParseArguments(args)
    if err != nil {
        return err
    }

    fmt.Printf("[+] Cargados %d dominios para escanear\n", len(domains))

    for _, domain := range domains {
        scanner.EnumerateSubdomains(domain)
    }

    subdomainsFile := "all_subdomains_combined.txt"
    scanner.CombineSubdomains("*.txt", subdomainsFile)

    fmt.Printf("[+] Encontrados %d subdominios únicos\n", utils.CountLines(subdomainsFile))

    scanner.ScanTakeovers(subdomainsFile)

    scanner.VerifyTakeovers("potential_takeovers_combined.txt")

    scanner.GenerateReport(domains)

    utils.Cleanup()

    fmt.Println("\n[+] === [🎀] Escaneo completado con éxito [🎀] ===")
    fmt.Println("[+] Revise los archivos de resultados y el informe generado.\n")

    return nil
}