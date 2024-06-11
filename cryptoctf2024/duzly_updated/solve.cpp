#include <NTL/ZZ_pXFactoring.h>
#include <chrono>
#include <vector>

using namespace NTL;

std::vector<uint32_t> p_1_bin = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0};

ZZ_pX fast_pow_p_1(ZZ_pX &x, const ZZ_pX &mod) {
  ZZ_pX res = x;
  int j = 0;
  for (auto i : p_1_bin) {
     std::cout << "Round: " << j << "/63" << std::endl;
    res = (res * res) % mod;
    if (i == 1) {
      res = (res * x) % mod;
    }
    j += 1;
  }
  return res;
}

void find_roots(ZZ_p h, const ZZ_pX &c, uint32_t argnum) {
  ZZ_pX mod;
  auto start = std::chrono::high_resolution_clock::now();

  SetCoeff(mod, 0, -h);
  mod += c;

  auto stop = std::chrono::high_resolution_clock::now();
  uint32_t duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "Init 2 Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  ZZ_pX x;
  SetCoeff(x, 1, 1);

  start = std::chrono::high_resolution_clock::now();

  ZZ_pX x_p_1 = fast_pow_p_1(x, mod);

  stop = std::chrono::high_resolution_clock::now();
  duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "Pow p-1 Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  ZZ_pX gcd;
  start = std::chrono::high_resolution_clock::now();

  GCD(gcd, x_p_1 - 1, mod);

  stop = std::chrono::high_resolution_clock::now();
  duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "GCD Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  Vec<Pair<ZZ_pX, long>> factors;
  start = std::chrono::high_resolution_clock::now();

  CanZass(factors, gcd); // calls "Cantor/Zassenhaus" algorithm
                         //
  stop = std::chrono::high_resolution_clock::now();
  duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "Factor Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;
  //
  std::cout << argnum << "factors = " << factors << std::endl;
}

int main(int argc, char **argv) {
  ZZ p = conv<ZZ>("18446744073709551557");
  ZZ_p::init(p);

  std::vector<ZZ_p> cs;
  cs.push_back(conv<ZZ_p>("1"));
  cs.push_back(conv<ZZ_p>("17761542461647558231"));
  cs.push_back(conv<ZZ_p>("13293668011354679701"));
  cs.push_back(conv<ZZ_p>("9204760597720472707"));
  cs.push_back(conv<ZZ_p>("8540722934676348527"));
  cs.push_back(conv<ZZ_p>("3568330912555059249"));

  std::vector<ZZ_p> hs(24);
  hs[0] = conv<ZZ_p>("2988030636007782305");
  hs[1] = conv<ZZ_p>("12072493504983501068");
  hs[2] = conv<ZZ_p>("6455555549858422687");
  hs[3] = conv<ZZ_p>("332674325673811430");
  hs[4] = conv<ZZ_p>("1365214988046232242");
  hs[5] = conv<ZZ_p>("8747631820355484079");
  hs[6] = conv<ZZ_p>("18123548747649932808");
  hs[7] = conv<ZZ_p>("13046626162506912628");
  hs[8] = conv<ZZ_p>("2218632231558076393");
  hs[9] = conv<ZZ_p>("3370337767665008202");
  hs[10] = conv<ZZ_p>("10801882347401505353");
  hs[11] = conv<ZZ_p>("12241743889746753324");
  hs[12] = conv<ZZ_p>("1408885656997934913");
  hs[13] = conv<ZZ_p>("580550489477911343");
  hs[14] = conv<ZZ_p>("18325674811173222161");
  hs[15] = conv<ZZ_p>("5163042577640987924");
  hs[16] = conv<ZZ_p>("4374658315402249035");
  hs[17] = conv<ZZ_p>("3049637019635323521");
  hs[18] = conv<ZZ_p>("4633465126861589844");
  hs[19] = conv<ZZ_p>("12895858433491142556");
  hs[20] = conv<ZZ_p>("2580453314653954697");
  hs[21] = conv<ZZ_p>("7139242178290800255");
  hs[22] = conv<ZZ_p>("12516366163786112763");
  hs[23] = conv<ZZ_p>("18065580967927811201");

  uint32_t argnum = std::stoi(argv[1]);

  ZZ_pX mod;

  auto start = std::chrono::high_resolution_clock::now();

  SetCoeff(mod, 0, cs[5]);
  SetCoeff(mod, 1, cs[4]);
  SetCoeff(mod, 2, cs[3]);
  SetCoeff(mod, 3, cs[2]);
  SetCoeff(mod, 16777219, cs[1]);
  SetCoeff(mod, 16777233, cs[0]);

  auto stop = std::chrono::high_resolution_clock::now();
  uint32_t duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << "Init Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  find_roots(hs[argnum], mod, argnum);

  return 0;
}
