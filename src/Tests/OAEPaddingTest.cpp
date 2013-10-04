#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Crypto, OAEPaddingTest)
  {
    QByteArray data;

    EXPECT_EQ(41, OAEPadding::MinimumPaddingLength());

    // test empty data
    QByteArray pad = OAEPadding::Pad(data, 50);
    EXPECT_EQ(50, pad.length());
    QByteArray unpad = OAEPadding::UnPad(pad);
    EXPECT_EQ(data, unpad);

    // test data with all 0's
    data.resize(20);
    pad = OAEPadding::Pad(data, 50);
    EXPECT_EQ(70, pad.length());
    unpad = OAEPadding::UnPad(pad);
    EXPECT_EQ(data, unpad);

    // test random data
    data = QByteArray("Some random text....");
    pad = OAEPadding::Pad(data, 50);
    EXPECT_EQ(70, pad.length());
    unpad = OAEPadding::UnPad(pad);
    EXPECT_EQ(data, unpad);

    // check invalid data
    pad[3] = pad[3] ^ 0xff;
    unpad = OAEPadding::UnPad(pad);
    EXPECT_TRUE(unpad.isNull());
  }
}
}
