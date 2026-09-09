import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                Text("NEXA")
                    .font(.system(size: 42, weight: .semibold, design: .rounded))
                Text("Private. Open. E2EE by design.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .navigationTitle("NEXA")
        }
    }
}

#Preview { ContentView() }
