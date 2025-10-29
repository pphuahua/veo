package report

import (
    "fmt"
    "os"
    "path/filepath"
    "veo/internal/core/logger"
    "veo/internal/modules/portscan"

    "github.com/xuri/excelize/v2"
)

// GeneratePortscanExcel 生成端口扫描 Excel 报告
// 输出列：IP, Port
func GeneratePortscanExcel(results []portscan.OpenPortResult, outputPath string) (string, error) {
    f := excelize.NewFile()
    sheet := "PortScan"
    f.SetSheetName(f.GetSheetName(0), sheet)

    headers := []string{"IP", "Port"}
    for i, h := range headers {
        cell, _ := excelize.CoordinatesToCellName(i+1, 1)
        f.SetCellValue(sheet, cell, h)
    }

    for idx, r := range results {
        ipCell, _ := excelize.CoordinatesToCellName(1, idx+2)
        portCell, _ := excelize.CoordinatesToCellName(2, idx+2)
        f.SetCellValue(sheet, ipCell, r.IP)
        f.SetCellValue(sheet, portCell, r.Port)
    }

    if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
        return "", fmt.Errorf("创建输出目录失败: %w", err)
    }
    if err := f.SaveAs(outputPath); err != nil {
        return "", fmt.Errorf("保存 Excel 失败: %w", err)
    }
    logger.Debugf("Excel报告已生成: %s", outputPath)
    return outputPath, nil
}

