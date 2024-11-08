#include <hwtrust/hwtrust.h>
#include <hwtrust/lib.rs.h>

using android::base::Error;
using android::base::Result;

namespace hwtrust {

rust::DiceChainKind convertKind(DiceChain::Kind kind) {
  switch (kind) {
    case DiceChain::Kind::kVsr13:
      return rust::DiceChainKind::Vsr13;
    case DiceChain::Kind::kVsr14:
      return rust::DiceChainKind::Vsr14;
    case DiceChain::Kind::kVsr15:
      return rust::DiceChainKind::Vsr15;
    case DiceChain::Kind::kVsr16:
      return rust::DiceChainKind::Vsr16;
  }
}

struct BoxedDiceChain {
    ::rust::Box<rust::DiceChain> chain;
};

// Define with a full definition of BoxedDiceChain to satisfy unique_ptr.
DiceChain::~DiceChain() {}

DiceChain::DiceChain(std::unique_ptr<BoxedDiceChain> chain, size_t size) noexcept
      : chain_(std::move(chain)), size_(size) {}

Result<DiceChain> DiceChain::Verify(
  const std::vector<uint8_t>& chain, DiceChain::Kind kind, bool allow_any_mode,
  const std::string& instance) noexcept {
  rust::DiceChainKind chainKind = convertKind(kind);
  auto res = rust::VerifyDiceChain(
    {chain.data(), chain.size()}, chainKind, allow_any_mode, instance);
  if (!res.error.empty()) {
      return Error() << static_cast<std::string>(res.error);
  }
  BoxedDiceChain boxedChain = { std::move(res.chain) };
  auto diceChain = std::make_unique<BoxedDiceChain>(std::move(boxedChain));
  return DiceChain(std::move(diceChain), res.len);
}

Result<std::vector<std::vector<uint8_t>>> DiceChain::CosePublicKeys() const noexcept {
  std::vector<std::vector<uint8_t>> result;
  for (auto i = 0; i < size_; ++i) {
    auto key = rust::GetDiceChainPublicKey(*chain_->chain, i);
    if (key.empty()) {
      return Error() << "Failed to get public key from chain entry " << i;
    }
    result.emplace_back(key.begin(), key.end());
  }
  return result;
}

bool DiceChain::IsProper() const noexcept {
  return rust::IsDiceChainProper(*chain_->chain);
}

struct BoxedCsr {
    ::rust::Box<rust::Csr> csr;
};

// Define with a full definition of BoxedCsr to satisfy unique_ptr.
Csr::~Csr() {}

Csr::Csr(std::unique_ptr<BoxedCsr> csr, DiceChain::Kind kind, const std::string& instance) noexcept
    : mCsr(std::move(csr)), mKind(kind), mInstance(instance) {}

Result<Csr> Csr::validate(const std::vector<uint8_t>& request, DiceChain::Kind kind, bool allowAnyMode,
    const std::string& instance) noexcept {
    rust::DiceChainKind chainKind = convertKind(kind);
    auto result = rust::validateCsr(
        {request.data(), request.size()}, chainKind, allowAnyMode, instance);
    if (!result.error.empty()) {
        return Error() << static_cast<std::string>(result.error);
    }
    BoxedCsr boxedCsr = { std::move(result.csr) };
    auto csr = std::make_unique<BoxedCsr>(std::move(boxedCsr));
    return Csr(std::move(csr), kind, instance);
}

Result<DiceChain> Csr::getDiceChain() const noexcept {
    auto result = rust::getDiceChainFromCsr(*mCsr->csr);
    if (!result.error.empty()) {
        return Error() << static_cast<std::string>(result.error);
    }
    BoxedDiceChain boxedChain = { std::move(result.chain) };
    auto diceChain = std::make_unique<BoxedDiceChain>(std::move(boxedChain));
    return DiceChain(std::move(diceChain), result.len);
}

} // namespace hwtrust
