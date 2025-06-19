package main

import (
    "fmt"
    "os"

    "github.com/theoffsecgirl/takeovflow/cmd/scanner"
)

func main() {
    if err := scanner.Run(os.Args); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}