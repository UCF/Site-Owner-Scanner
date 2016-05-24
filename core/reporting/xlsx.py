from core.models import ScanResult
import xlsxwriter


def export_xlsx(session):
    workbook = xlsxwriter.Workbook('results.xlsx')
    worksheet = workbook.add_worksheet()

    bold = workbook.add_format({'bold': 1})

    worksheet.set_column('A:E', 30)

    worksheet.write('A1', 'Domain', bold)
    worksheet.write('B1', 'IP', bold)
    worksheet.write('C1', 'Port', bold)
    worksheet.write('D1', 'Response Code', bold)
    worksheet.write('E1', 'Owner', bold)

    results = []
    for i in session.query(ScanResult).all():
        results.append([i.domain.name, str(i.ip.ip_address),
                        str(i.port), str(i.response_code), i.owner])

    row, col = 1, 0
    for domain, ip, port, response_code, owner in results:
        worksheet.write(row, col, domain)
        worksheet.write(row, col + 1, ip)
        worksheet.write(row, col + 2, port)
        worksheet.write(row, col + 3, response_code)
        worksheet.write(row, col + 4, owner)
        row += 1
