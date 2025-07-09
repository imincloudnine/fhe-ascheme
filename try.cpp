#include <helib/helib.h>
#include <iostream>
#include <vector>
#include <random>
#include <numeric>

using namespace std;
using namespace helib;

// Generate fresh random mask R
Ptxt<BGV> generate_mask(const Context& context) {
    vector<long> R(context.getEA().size());
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long> dist(0, context.getP() - 1);
    for (auto& r : R) r = dist(gen);
    return Ptxt<BGV>(context, R);
}

// RoundInit: Server generates initial masked ciphertext
pair<Ptxt<BGV>, Ctxt> RoundInit(const PubKey& pk, const Context& context) {
    Ptxt<BGV> R = generate_mask(context);
    Ctxt c0(pk);
    pk.Encrypt(c0, R);
    return {R, c0};
}

// NodeProcess: Each node adds encoded (x_i * d_i, x_i * s_i + d_i) to 2 slots
Ctxt NodeProcess(const Context& context, const PubKey& pk, const Ctxt& cin,
                 long xi, long si, int i, long di) {
    size_t N = context.getEA().size();
    vector<long> vec(N, 0);
    vec[2 * i] = (xi * di) % context.getP();
    vec[2 * i + 1] = (xi * si + di) % context.getP();
    Ptxt<BGV> pt(context, vec);
    Ctxt cout = cin;
    cout += pt;
    return cout;
}

// RoundVerify: Server decrypts and verifies all node slots
vector<long> RoundVerify(const SecKey& sk, const Ptxt<BGV>& R,
                         const vector<pair<long, long>>& xsis,
                         const Ctxt& cfin) {
    Ptxt<BGV> V(sk.getContext());
    sk.Decrypt(V, cfin);
    for (size_t j = 0; j < V.size(); ++j) {
        V[j] = (V[j] - R[j] + sk.getContext().getP()) % sk.getContext().getP();
    }

    vector<long> out;
    for (size_t i = 0; i < xsis.size(); ++i) {
        long xi = xsis[i].first;
        long si = xsis[i].second;
        long Pi = V[2 * i];
        long Qi = V[2 * i + 1];

        // Compute modular inverse
        long mu;
        if (!InvModStatus(mu, xi, sk.getContext().getP())) {
            mu = InvMod(xi, sk.getContext().getP());
        }
        long d_star = (mu * Pi) % sk.getContext().getP();

        if ((xi * si + d_star) % sk.getContext().getP() != Qi) {
            throw runtime_error("Verification failed at node " + to_string(i));
        }
        out.push_back(d_star);
    }
    return out;
}

int main() {
    // Parameters
    long p = 4999;
    long r = 1;
    long bits = 300;
    long c = 2;
    long m = 8192;
    size_t n_nodes = 4;

    // Setup
    Context context = ContextBuilder<BGV>().m(m).p(p).r(r).bits(bits).c(c).build();
    SecKey sk(context);
    sk.GenSecKey();
    const PubKey& pk = sk;

    // Per-node constants (xi, si)
    vector<pair<long, long>> xsis(n_nodes);
    for (auto& [xi, si] : xsis) {
        xi = 3 + rand() % (p - 3); // Avoid xi = 0 or 1
        si = rand() % p;
    }

    // Server initializes
    auto [R, c0] = RoundInit(pk, context);

    // Simulate sensor readings and node processing
    Ctxt c = c0;
    for (size_t i = 0; i < n_nodes; ++i) {
        long di = rand() % p; // Random sensor data
        c = NodeProcess(context, pk, c, xsis[i].first, xsis[i].second, i, di);
    }

    // Final server verification
    try {
        auto readings = RoundVerify(sk, R, xsis, c);
        cout << "Verified readings:" << endl;
        for (size_t i = 0; i < readings.size(); ++i)
            cout << "Node " << i << ": " << readings[i] << endl;
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }
    return 0;
}
