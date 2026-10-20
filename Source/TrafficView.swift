import SwiftUI

struct TrafficView: View {
    @ObservedObject var model: GuardModel
    private var selected: TrafficRecord? { model.traffic.first { $0.id == model.selectedTrafficID } ?? model.traffic.first }
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Входящие и исходящие данные").font(.system(size: 19, weight: .semibold))
                    Text("200 последних записей · хранение в памяти · URL без query · известные секреты скрыты")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Очистить") { model.traffic.removeAll(); model.selectedTrafficID = nil }
                Button("Экспорт JSON…") { model.exportTraffic() }.disabled(model.traffic.isEmpty)
            }.padding(20)
            Divider()
            HSplitView {
                List(model.traffic) { record in
                    Button { model.selectedTrafficID = record.id } label: {
                        VStack(alignment: .leading, spacing: 5) {
                            HStack {
                                Text(record.method).fontWeight(.semibold).foregroundStyle(.mint)
                                Text(record.kind).foregroundStyle(.secondary)
                                Spacer()
                                if let status = record.status { Text(String(status)) }
                                if !record.warnings.isEmpty { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                            }.font(.system(size: 11, design: .monospaced))
                            Text(record.url).font(.system(size: 11)).lineLimit(2).foregroundStyle(.primary)
                        }.padding(7).frame(maxWidth: .infinity, alignment: .leading)
                            .background(model.selectedTrafficID == record.id ? Color.indigo.opacity(0.2) : .clear, in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain)
                }.frame(minWidth: 280, idealWidth: 360, maxWidth: 440)
                ScrollView {
                    if let record = selected {
                        VStack(alignment: .leading, spacing: 18) {
                            Text(record.url).font(.system(size: 14, weight: .medium, design: .monospaced)).textSelection(.enabled)
                            Text("\(record.method) · \(record.status.map(String.init) ?? "—") · \(record.note)")
                                .font(.system(size: 12)).foregroundStyle(.secondary)
                            ForEach(record.warnings, id: \.self) { warning in
                                Label(warning, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.system(size: 12))
                            }
                            block("Исходящие заголовки", record.requestHeaders)
                            block("Исходящее содержимое", record.sent)
                            block("Входящие заголовки", record.responseHeaders)
                            block("Входящее содержимое", record.received)
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(22)
                    } else {
                        VStack(spacing: 15) {
                            Image(systemName: "arrow.up.arrow.down.circle").font(.system(size: 44)).foregroundStyle(.secondary)
                            Text("Запустите Claude с включённой диагностикой")
                            Text("Запросы CDP, текстовые ответы и доступные потоки появятся здесь. Записи TLS-шлюза показывают только адрес и объём зашифрованных данных.")
                                .font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        }.frame(maxWidth: .infinity).padding(40)
                    }
                }.frame(minWidth: 470)
            }
            Divider()
            Text("Содержимое может включать переписку. Внешние native-процессы, MCP и Cowork через CDP не видны. Большие и некоторые потоковые ответы могут быть неполными.")
                .font(.system(size: 10)).foregroundStyle(.secondary).padding(12)
        }
        .frame(minWidth: 850, minHeight: 620)
        .background(Color(red: 0.055, green: 0.065, blue: 0.095)).preferredColorScheme(.dark)
    }
    private func block(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 13, weight: .semibold))
            Text(text.isEmpty ? "—" : text).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
        }
    }
}
