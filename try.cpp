#include <helib/helib.h>
#include <NTL/ZZ.h>
#include <iostream>
#include <vector>
#include <random>
#include <numeric>

using namespace std;
using namespace helib;
using namespace NTL;

// Generate random mask R
Ptxt<BGV> generate_mask(const Context& context) {
    vector<long> R(context.getEA().size());
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long> dist(0, context.getP() - 1);
    for (auto& r : R) r = dist(gen);
    return Ptxt<BGV>(context, R);
}

// Initialization by server
pair<Ptxt<BGV>, Ctxt> RoundInit(const PubKey& pk, const Context& context) {
    auto R = generate_mask(context);
    Ctxt c0(pk);
    pk.Encrypt(c0, R);
    return {R, c0};
}

// Node operation: add two-slot contribution
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

// Final verification by server
vector<long> RoundVerify(const SecKey& sk, const Ptxt<BGV>& R,
                         const vector<pair<long, long>>& xsis,
                         const Ctxt& cfin) {
    Ptxt<BGV> V(sk.getContext());
    sk.Decrypt(V, cfin);
    long p = sk.getContext().getP();
    for (size_t j = 0; j < V.size(); ++j) {
        V[j] = (long(V[j]) - long(R[j]) + p) % p;
    }

    vector<long> out;
    for (size_t i = 0; i < xsis.size(); ++i) {
        long xi = xsis[i].first;
        long si = xsis[i].second;
        long Pi = long(V[2 * i]);
        long Qi = long(V[2 * i + 1]);
        long mu = InvMod(xi, p);
        long d_star = (mu * Pi) % p;

        if ((xi * si + d_star) % p != Qi) {
            throw runtime_error("Verification failed at node " + to_string(i));
        }
        out.push_back(d_star);
    }
    return out;
}

int main() {
    long p = 4999, r = 1, bits = 300, c_param = 2, m = 16384;
    size_t n_nodes = 4;

    Context context = ContextBuilder<BGV>().m(m).p(p).r(r).bits(bits).c(c_param).build();
    SecKey sk(context); sk.GenSecKey();
    const PubKey& pk = sk;

    vector<pair<long, long>> xsis(n_nodes);
    for (auto& [xi, si] : xsis) {
        xi = 3 + rand() % (p - 3);
        si = rand() % p;
    }

    auto [R, c0] = RoundInit(pk, context);
    Ctxt ctxt = c0;

    for (size_t i = 0; i < n_nodes; ++i) {
        long di = rand() % p;
        ctxt = NodeProcess(context, pk, ctxt, xsis[i].first, xsis[i].second, i, di);
    }

    try {
        auto readings = RoundVerify(sk, R, xsis, ctxt);
        cout << "Verified readings:\n";
        for (size_t i = 0; i < readings.size(); ++i)
            cout << "Node " << i << ": " << readings[i] << endl;
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }
    return 0;
}
