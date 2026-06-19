"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const blocktemplate = require("../build/Release/blocktemplate");
const blocktemplateJs = require("../index.js");
const rtm = require("../rtm.js");
const bitcoin = require("bitcoinjs-lib");
const varuint = require("varuint-bitcoin");

const cases = [
  {
    name: "arq",
    variant: 16,
    blob: "1010c59099c206028309f83a444da29afb16cc97126b0d82a0ef9dacdc5f5384e4d14f2bed221f00000000030005bbd769abd769abd769abd769abd769abd76901ff99d7690580c8afa02502c7a7d056ac171af27f081eb7113ee31eb6eac4c523960f31bc54ae4150fd087a80c8afa025022a74a3c4c36d32e95633d44ba9a7b8188297b2ac91afecab826b86fabaa7091680bcc1960b02a42e0bf2c44c7c5f43798f4be091a04d36e21b7a2f85008ff939dc028c1d14e980bcc1960b02c8b180ae1eef14bb14953eb6b0f8d66111c80067dfe9e689fdf72cf1b0d9d58580bcc1960b027d3ab388e3e7844bc42562edf05fb34d4b30b281b1307c75d7d3acfc90ed69b57601a15624111f421a5b16fd3350b5b234d288aa9e369a090fcdaeab7079361a74600211000000228f09650000000000000000000001cb6e8a28b50d5427f24dd6ede582e5eb895d739ad2cfe7eb7df31d7dcf1531c47200000000000000000000000000000000000000000000000000000000000000000000",
    expected: "1010c59099c206028309f83a444da29afb16cc97126b0d82a0ef9dacdc5f5384e4d14f2bed221f000000006ebc660a5f50595d256087798e91ff9184878de2db66d791108ec4149dcd01fc01"
  },
  {
    name: "bloc",
    variant: 1,
    blob: "0500ecb2ecb40646f61cfb8f3eb6f3527297eadd29125668008dc74c1ebb177cfb7d5c7c498dcd000000000199b25c01ffe7b15c043c02e42fc85c385aa98b9e83a75481a3fcd2ad049d59f3535c2775a15fae521aa37fc8010259fe9bb8bddfabed25331c90c1b478edb76fd9a94ced48c7b220498936f63268a01f02cbb7bf2ea054b438040c70bf8ba6c530b9890c0c8ca7019fef1c49d010321f61a08d060214c04c168d52662ac27d43c08c4941c4d7db9955bff0ec7e7ce1f0cd5f3bc68034014574cd7358bdee9f682543d2fa0cc23b207bf676688f40fd425d4f0477110cab02110000000000000000000000000000000000010df5931907c66fac569c743451aad0936db4d70f4d0fbcec44c504a2e02bd260",
    expected: "0500ecb2ecb40646f61cfb8f3eb6f3527297eadd29125668008dc74c1ebb177cfb7d5c7c498dcd000000004baf51b919538baa7bdbad14d2b63817df2d301f6e7ccd9cf78ff95adad647a702"
  },
  {
    name: "msr",
    variant: 6,
    blob: "08089eb3ecb406b35852af53db5ed822f0c51cfcfeb36a0c83fa55230a791add87087d221308c70000000001abd2c30101ffefd1c30101f7d7c0c084110220323306fc36cf0fed316f4d90f6ce0e04ec5b8e26b52886025f7a77957676cc340165706e1dd751a5bd9a72e58caf30104216b60fba751e8d681af90bc4df00cdd40211000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    expected: "08089eb3ecb406b35852af53db5ed822f0c51cfcfeb36a0c83fa55230a791add87087d221308c700000000ab937b64d0d1087c03155686ae5bdd27b79233f43dae45977f620b863590596c010000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    name: "ryo",
    variant: 4,
    blob: "0909bcb7ecb406e417dd02e55e8c3f6368749df3e761b000f87001e28ccb9c24f1d65f2cc848d70000000003e5f93701ffa9f9370181a0f693710231510ef639f6848581cc3df0ab1783f73fd401d4ab03df62dfad68f8557bad943401f3cc08c30d31a225b46514edfccc4b3c0d429cac30b23e1e4fd9e1c514f5b350021100000000000000000000000000000000000000",
    expected: "0909bcb7ecb406e417dd02e55e8c3f6368749df3e761b000f87001e28ccb9c24f1d65f2cc848d7000000008c95c259fa076f11347c4129bf1020da140d44f3948410c0f3a77d1b4d18a21f01"
  },
  {
    name: "sal",
    variant: 15,
    blob: "0a0ad3efb6c706668aaad0289b8bf3bf8cd109d6da4107b48f4242185fa6d50b78575c55e728b400000000043c01ffdcb91401bac68dc22104fd2c8f800bd4c33b96cde12515224a403ea052736d98cf8c5d5a5ff4a66dddc00453414c3151042efafd5871735ab1f3dcb6c380e595b2d0340136a86969f8e7a0c4bd739cd6163b38e3c76f1fb443f7a552e755b305b11c53510211000000000000000000000000000000000001ceb1c3b00800043c01ffdcb91400020200020001c0d11e47cd1d4ef51d152f6f186f76a91623b8ce922687ce8c907a5dfda26237",
    expected: "0a0ad3efb6c706668aaad0289b8bf3bf8cd109d6da4107b48f4242185fa6d50b78575c55e728b4000000003dc5e186a15e0b48571088e8b3c0a04597ff88a3dc3661cae2f0a2a8a2a81d7403"
  },
  {
    name: "sal_v11_create_token",
    variant: 15,
    blob: "0202959aef3a424242424242424242424242424242424242424242424242424242424242424217171717050001ff0000000100000509000000092a011111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233445566778899aabbccddeeff1020304050600353414c03544f4b070103544f4b0101c0843d0309546f6b656e697a65641d68747470733a2f2f6578616d706c652e696e76616c69642f746f6b656eabababababababababababababababababababababababababababababababab00",
    expected: "0202959aef3a424242424242424242424242424242424242424242424242424242424242424217171717910145209475e1f1492f07071ee36e0803a16002c8b8efa80ebdfe6a16d2456902"
  },
  {
    name: "sal_v11_rollup",
    variant: 15,
    blob: "0202959aef3a424242424242424242424242424242424242424242424242424242424242424229292929050001ff000000010000050d0000000a009191919191919191919191919191919191919191919191919191919191919191929292929292929292929292929292929292929292929292929292929292929203544f4b03544f4b009393939393939393010194949494949494949494949494949494949494949494949494949494949494949595959595959595959595959595959595959595959595959595959595959595c0c40700",
    expected: "0202959aef3a424242424242424242424242424242424242424242424242424242424242424229292929bb4e953b681069104a0ec41a4fcb0189381b8a21e23e47efeef263f8d8d9affe02"
  },
  {
    name: "xla",
    variant: 14,
    blob: "1010b9b7ecb4060404b45248c01f9a65d5b2e5ec3fd875de7e8bff8eb79453fd87c0d39e04546b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b6ea3f01fffae93f01dcc50a0308686987f2c9643b5c20a29f1d124b4330b5e7c94f242f4be451303a82a2c635123401c2ea0da83a76b72a1e4b581143febf8f08155eeb3482955e2b4d0c43507ebba4021100000000000000000000000000000000000000",
    expected: "1010b9b7ecb4060404b45248c01f9a65d5b2e5ec3fd875de7e8bff8eb79453fd87c0d39e04546b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004fed0302f50f72bf1ac330a367b4ea32a24fb5de5b91a927392eaa318b342cca01"
  },
  {
    name: "xmr",
    variant: 0,
    blob: "1010f4b3ecb406a7e85c45ba044af4a16e0e790032f31727e3daef1a7da5ab12c9894c191713e30000000002a18ec30101ffe58dc30101c084aa98d21103d71cd8a7478f0c74e191f3dac85b4c396ec76a07311a94db04721676634ab49b1e34014f9b1e0434876de264409d8f024f5f61fdcb9297ef671518310e7add0e69bc270211000000000000000000000000000000000000238dc39cf2f9eef8084b911d6086075ea57b58793ec2a0a8683f5d890a5be1c92583892a3f5127cb3469da37719047fbdd5bc32034c996a9e3919485d36ac5f609c646379ca888796d7485d403f45ab2230b66920c8f0b1e160d4b6529f531ca95bc04dfc96e7643a9f86526ba4e899fa52d2279abf2cf8b60e4be19f9f9b293211f508353cb5496f04b7e9824395828385e7724a2e2fa42097962028fd7c5083fa3e827d9f46dbf3741181d4f4897aea254bbc2081a3455603c81bfd75961541cb3f1ad55fa277111b5e4b3b7ce10c1bbdca7e158d36deac6c09ef9827edea7d6dce44f1145831d29d7ac59e497050af0a19de855302ff70079e60761d6bae70dc45a766e7088e764e6950e5a9704e03e5a455b23a572af2950c613d6d109b2007a7c943e4b0c2513ced71179b0dd0388fa0c397b83d4ebeb616cbe89c6c2d12972bdbbe845f78189fd3b0494bcac392b8ec9a6c2d49d88c391c54fd2bf0ba45aded1dbff66fe6311c293b6ae1f47127ad936890cfc2379427be0360b68007ae3dd56083a4eb90d736370b23471dd5d2b7ee2107bd44016e20b9a948e745b2de2cbcd7780e981b0eeb646175137e8b42a9b9724263d9a84d9ba892caa209c73ca03ab832e504d309a6714e8554b13b3c05f306f0e46c06c801978e7f69727b8333709fe7c836286cefd36ef22a4681653d04a96ce91d5f97aee107f93cd5f57c3f5f553e435a910c60f426b3f3658754e72a55ea8b40eda985147558159296bfa23ab9cbbd2e8316a00b87ea81195d8b4a3d4ec2889a788af0d4ce53b4e261a1087eae0f54cc92132f87a5aadadd3ea70228df71a615b85a1d96bc031d08e6fafb41117b055c9db533d27fcacc14a251369654c377d451e2eeb7aa7d26ff12542c5b7194d2b783b493435c0bee44b9ee315aa373dd79ed7abebe2095e547867f0db8cda9a8544f306a74e96a7023e637642f63bc5fa27dcfae1a59655b7170fee88c7362f676b6b4e5aee6c94cdfda39075138bf4fb0da0f7490ea33d85d8d72a23695f30f14f65edd4715aacc897d6be2df0e6566c3d484945f2b4ac5e6dab45306d2e8704ba8590388d7d41620ed4171701c5d8eab8b0e1192075606b70dc00014089e31fee4ae2aaa3dc49c9018ec93497818eb1348bedf3b2d0af7ccc4bb5bb151a7e9b1759d46db0e3b4acb08f639ae61a43aff57f1f9f8baff9205d4350733a8bd2f99acb417ef81fd5affb56cf85019fc23bcc03359b0d57c62a94efae9028a7353f11edc5f304fd59cc24ecfcd40db5e5354ebb288d64934c4bf3e56a37c612043d49335e52a1788998cbf3a1cc09bc78c9ffbac1346a4fad340727ee9aa20c00ebf5131556fbdbf842469d31c8121feae78c3a56ba1eae5bde78c18371108601e8ae7f5698d0918be8e52afc500fa67c35b46e8011b686e9a5e20008b7dfd3eb85011f54a70832823611dc06373d1b98052a503313a6e4d0eab3ad97f04dac2305cbb4fa094c6634270289593f90ffcd460529d0835bdfe780074488d531ebb06558ba4b28ece031cfd981062beec659c6a50addfefaf2e4e1e11f95",
    expected: "1010f4b3ecb406a7e85c45ba044af4a16e0e790032f31727e3daef1a7da5ab12c9894c191713e300000000980c1b19961064ad5ceba387074e29030eac8378bcb38f5a50189f8892c4578324"
  },
  {
    name: "xmv",
    variant: 8,
    blob: "0d0d9ab8ecb406317c2fb5d01d1baccedab49650312ee4c5390f0f569a77f6703f9c617e9de92f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002d5ef8e0101ff99ef8e0101bea394bad10802a50df09ab1bbdb1e9be7e626b9746266c0a8193f649db53affe59ff69ff268843401ed630c83e0a68cc91762ba50312078e4299aff7eb9aa011c751c760c4ee15f2c021100000000000000000000000000000000000000",
    expected: "0d0d1a1c9b6600000000317c2fb5d01d1baccedab49650312ee4c5390f0f569a77f6703f9c617e9de92fe8e1af3e87d14e8aa51dd2cc397f8d455ac486ec069fb832b45fe7123dca5d42010000000000000000"
  },
  {
    name: "zeph",
    variant: 13,
    blob: "050592b8ecb406407f1bf945d1f437a1705b323f46a86e18d0882a516f7b0582a4b208bf577e710000000090cbdb40c1020000903f4ebcb9020000f0d8bbdd4c00000070b623b84d0000006045baf33701000070a2fd163701000040521b4fda05000010758b35c8050000131c9b66000000005f9669b40d9a190f51d226502bad1bbc8fea45e18f4c87dee8cd273efbfd69e27219defe1a6480b68f1a5205e72d63246d5565a2f19bbfc9816005bc8ebb89f703c99d1201ff8d9d1202b5c3c8a38099020208f52c744b1455ec58ab17ea0202a64b605ed1c6cffc88fd41eb3cc76b7d2abd045a455048cdfbfba6f1dd120235aebd0d4d356555503a5460b569a4e0e8b7ded8757b85531ed5b02fa2d998ba045a455048ce55014b0868384957bedcd9b70d6c141f3f811a41bcee8f44813f92fcc6cb428e037c021100000000000000000000000000000000000129cb6a3ab186d3fbccedb4fcc119931ab8e9aee73f4aea4e77778a0ba987a99e0000000000",
    expected: "050592b8ecb406407f1bf945d1f437a1705b323f46a86e18d0882a516f7b0582a4b208bf577e710000000090cbdb40c1020000903f4ebcb9020000f0d8bbdd4c00000070b623b84d0000006045baf33701000070a2fd163701000040521b4fda05000010758b35c8050000131c9b66000000005f9669b40d9a190f51d226502bad1bbc8fea45e18f4c87dee8cd273efbfd69e27219defe1a6480b68f1a5205e72d63246d5565a2f19bbfc9816005bc8ebb89f7220309a73319964e8560ce2be3f523d1cd4f36d366a503acb1d44dadeb9e8c8101"
  }
];

for (const testCase of cases) {
  test(`convert_blob ${testCase.name}`, () => {
    const actual = blocktemplate
      .convert_blob(Buffer.from(testCase.blob, "hex"), testCase.variant)
      .toString("hex");

    assert.strictEqual(actual, testCase.expected);
  });
}

const realDaemonTransactionVersionBlockCases = [
  {
    name: "xmr_v1_height_1000000",
    blobType: 0,
    txVersion: 1,
    expectedBlockId: "a886ef5149902d8342475fee9bb296341b891ac67c4842f47a833f23c00ed721",
    blob: "0102ad91a6b70509930781258c24007085a407703a6c34b2a560fef7d2c51879fb5622ff3c17d65edc000001fc843d01ffc0843d04dbf28af418021f81f90ac3b38a5136c599f0a5f34585786fe7ed44c0bf3824d799548d2488468088aca3cf0202ae47c917ed0d19d7d31f225be374924c668bb811f9880644266a5431c1bef2f880b081daaf1402bb1c9040d05c870237dea615f82fce937f047ef655be812435ecf1aedb89016380c0f9decfae0102fac6e7c0224d389abcce7bcf982e3fbee87e47e3a442d115e4db9262cfecf67f2b019096dbc5cb0f8f246fd86a5f395361ae82fbb7b7b2a4b6e33c91df1c67489a34020800000002410c25f400"
  },
  {
    name: "xmr_v2_height_2000000",
    blobType: 0,
    txVersion: 2,
    expectedBlockId: "dc2ef85b049311814742f543469e3ec1b8d589e68434d9f220ce41072c69c39e",
    blob: "0c0cc2faa5f0055b0ad4da7bd13add13136552814aad6b4c32c95d29bf03968dd57f3de6131835ad92000002bc897a01ff80897a01ef9096d9af3b022ee15ed05f71cc4d3dda3d1f3fe7724af90c3dd15e5d1d7886d42639d0cc7be73401f9b95f4fae7e4ce7192b78f9645a25307e93bdc510be558006cf65194d23d18c0211000011eb7f5956130000000000000000000000"
  },
  {
    name: "ryo_v2_height_1",
    blobType: 4,
    txVersion: 2,
    expectedBlockId: null,
    blob: "0101df92d6c7056eb04b6b8c68049a76206fe2805ede5f7465c03b7112850d3262a067b9914dacbc137abf023d01ff01018080e59a7702b4f7c8318c74fe90d333a74838f2152719a6980838c44859eb18974c533dc9cb2101113a12d7b5e6b3a0d7e97affd1b75481f692abe1d2eb3e90346123d6e74a111f0000"
  },
  {
    name: "ryo_v3_height_1000000",
    blobType: 4,
    txVersion: 3,
    expectedBlockId: "95ebebbb35cc9cefbfcd0794f52403e7ccdad909d6e40aef748c9c8efa709cf0",
    blob: "0909da81dabe060222d22f1e64fe086b55737104be3e7dd53cccde795398034e72deafe8101a54a647000003fc843d01ffc0843d0180cbabfe830102e87ad3278012c9f0fe4bf48b3d562dce6f70e04bf433c449ac94740b534dc00334011fa3969aec853fa259ee8adb1c0406a776346162ef588f0027543b793da01f9602110000000bcf476c0000000002000007fc000000"
  },
  {
    name: "zeph_v2_height_1",
    blobType: 13,
    txVersion: 2,
    expectedBlockId: "233351919978ff54c657d45ef1fc7298ea4c97779a4cf1f73555db06f71940fa",
    blob: "0101b48fd1a306f53afd86c39b60858bd5fc9ea9f4b8e688f79c2b0158b211463bb344947305051040603c000000000000000000000000000000000000000000000000023d01ff0102eeeecdd49bd903028cd872775519a780389e4c58eeaef9f22a7fbc0f2c94c4d1aeb1f8f36b7cdc3a045a45504847d6d6dbfdf3180203acb9bc5b4694f2b4f44d1626dace46bd96b3419ac117e9755c2ee5e786e2fd045a455048fa4201e16d530ed647d59880360e7326e3198e43824f487f4c08e71282516abb1971c90158666666666666666666666666666666666666666666666666666666666666660000000000"
  },
  {
    name: "zeph_v3_height_790000",
    blobType: 13,
    txVersion: 3,
    expectedBlockId: "e5306333bab59ecd0eb0d4db0f0ed909133afba41461e9591504ca58bac263be",
    blob: "0b0bc8a783d1060beb4ea1774aeb50f8959b5e6b0752569f99acd45a5d827edcc347bee6f15ffaff2b0d0060fc4efe46000000a0ce0fa545000000c0cefd97fb020000000fd3a10a030000601ca41a0f010000a0a9efd10c01000000ae63b319030000d0cd68d30903000040f79d92be010000c7d3206a00000000da409fc26ef6217e557e0e574bd941d8eb382f49ebf9bf5798c0770baa97b7fcebf893c6211ce5ed95cf7d7720a0994c6cb0d4835611096db8f07bd98e7ef37703ac9c3001fff09b300193d690a39b7d02bfc56107ce78ca555de003c7ac46ea315aa70de4f91fd564ad793aa6426404d8035a5048db34014e06f7d9bba4692433b0e02f2881bdcf02feb302d20c6ad066ba123978c86cbb02110000000e175a98000000000000000000000000000000"
  },
  {
    name: "xla_v1_height_1",
    blobType: 14,
    txVersion: 1,
    expectedBlockId: "24a4f01ec0874783d63fd6ced2da1e1009941bf379e33426043d55a8d33fee5b",
    blob: "010ce2f493f9053fa5c8976978f52ad7d8fc3663e902a229a232ef987fc11ca99628366652ba993545efbb013d01ff0101904e0279c85667778b79bdfc242f40c78c94a5e5d5755887652432efc4a7e30bfd1ce82101a9ebcca1ec9b4ff80d0df67c2252b5b604f9c5f96b7ca7cd948c4e20d3602bfa00"
  },
  {
    name: "xla_v2_height_1000000",
    blobType: 14,
    txVersion: 2,
    expectedBlockId: "5d17323d588da6727bdb37ad32bd1454d146cc63f6441b52ee597ede5166566f",
    blob: "10109eefa2b2060edda949258bd26d0e2404cff0d58040ab2b4645f98aaa855355ad7c88ae87bb4ca26bda05b95a55f807ada486437f72e9530b62898142e79768de2baac7f46ef83f9d0fcd0b9457cb4a5d4d8c369bb0e94417bdc149e997cc7d7da0550dc7a1945ebf0402fc843d01ffc0843d01bfe30a03207ef1d487aa94e10ae656c96fc75b3eeaeb1322fcfab7dfe878b9dd05d43e9bb4210105c0bded24276005cd6a94524f09250427adda0691427bfbbb35f9fe3e79bc900000"
  },
  {
    name: "sal_v2_height_1",
    blobType: 15,
    txVersion: 2,
    expectedBlockId: "b6b45052e7e182ebaeb14ab713db29ad979115e664d766aa0910e325564a27a6",
    blob: "0101cba994b4061f5f4102fd000d6e4258856f57a0056ef653c56e7e25a6ad13b8bb31db00ee7b6484a8f2020001ff0101bca2b8902e037d361e2f594efafa4ca0bdf1fa79c95d9a2fe4b7db43029b8e8579b827ce47250353414c3c3c21017c29242ed3820b155b1884dd08d2d86f773a243710bc9a42e9f7de7ffecebee601cf888ec40b00020001ff01002301690f880e55c6eb1fa31a7d75f1fa2fd2236716924232ed45c93e2c62da874b020400020000"
  },
  {
    name: "sal_v5_height_500000",
    blobType: 15,
    txVersion: 5,
    expectedBlockId: "364a28d5908e3cb00f5eb7afed485c911af69e67d2f2ea4fc83a242a652e64c9",
    blob: "0b0be1f4f5d0063b30f884b37d27e3676e45ab5d1f092fcb7abdb445eac3881521d5838c1e4e1815290f00053c01ffa0c21e02c1ffadf90804ed3079acf178aef9de96f9e58449bb0a99f312464fbcecec92e338cc3ee1f3830453414c31ac63cb468f2140a6e5b721f63135228afdb6cf84b2eebc1504f66279df3524b40f624ebc0bf4a2adee38988b12d1ab923905ab6ca32fa9f0090453414c31e328dd1540c612be2da5dae2d151f86312d5e74c0402a2552d644c869f91eb3fd30ad7ffca13b1ec9fc2cc041a1b5c2fb5da88f1f25bd1e339cdd53bed85187524591711e13df373b76df4c61dc9c4b6038af5ae783a020832021406efeb407201c0cc9baf0500053c01ffa0c21e00020200020000"
  },
  {
    name: "arq_v2_height_1",
    blobType: 16,
    txVersion: 2,
    expectedBlockId: "6115a8e9902af15d31d14c698621d54e9bb594b0da053591ec5d1ceb537960ea",
    blob: "0708f6f88ad90560077b4d5cd49a1278d448c58b6854993d127fcaedbdeab82acff7f7fd86e328f985874c021301ff01018080c39edda6a90d020b90d9013afec274cec5df28d85bb25c817ed575f54de38311da8cfc48b7a133210172028a94f017a886090b9e5814419a8a0aa4c089c992805444af726a582a63290000"
  },
  {
    name: "arq_v3_height_1957265",
    blobType: 16,
    txVersion: 3,
    expectedBlockId: "959fd3ec99371c776c502e73e2b3c27bbef178376d3b160a93461151a8462ecb",
    blob: "1313b7cd8dd10614ff2a77ff4dcce7900aa62cedfff5058bdf43e59854e564ab18f93ec8ee9871cfb10600030005c1bb77a3bb77a3bb77a3bb77a3bb77a3bb7701ff91bb770580c8afa02502684338e352a9864b95883e34f5f7d2abf3b2153303c542cb1582255ba5756e5c80c8afa025028f94f28b138ef2961c74a740df250e2407e017604ab55ea376ebad06f458210d80bcc1960b02469ec76d0fa84e4fe4bc8de91f1510e2fa1f4a4116b8052f9ca9d07785aabffe80bcc1960b02beb9aa0f95742132cc67f7a04f1af33fe19fd41c0f8cfe2f73bca55e5cc89c4780bcc1960b02f2d09e6009c85b80d2e621283de21ead5357a713231c54755049536d42096c117601cc3796dca54db0728eac0eab578adc9ee3efda29adfc5a01d818237f21c5c76e0211000000046a5dc7020000000000000000000106ff2a10bca5c813c42747f29f3718752d2c85e13665615bfc27c61aef81eb6b72c442b8c2be6b9175211390d4dbf3d3c6b9c8132517335eabbffce8b68da71b360000"
  }
];

const existingTransactionVersionBlockCases = [
  {
    name: "bloc_existing_fixture",
    blobType: 1,
    txVersion: 1,
    expectedBlockId: null,
    blob: cases.find((testCase) => testCase.name === "bloc").blob
  },
  {
    name: "msr_existing_fixture",
    blobType: 6,
    txVersion: 1,
    expectedBlockId: null,
    blob: cases.find((testCase) => testCase.name === "msr").blob
  },
  {
    name: "xmv_existing_fixture",
    blobType: 8,
    txVersion: 2,
    expectedBlockId: null,
    blob: cases.find((testCase) => testCase.name === "xmv").blob
  }
];

const transactionVersionBlockCases = realDaemonTransactionVersionBlockCases
  .concat(existingTransactionVersionBlockCases);

function findTransactionVersionBlockCase(name) {
  const testCase = transactionVersionBlockCases.find((candidate) => candidate.name === name);
  assert(testCase, `missing transaction version fixture ${name}`);
  return testCase;
}

test("cryptonote parser accepts supported transaction versions from real block blobs", () => {
  for (const testCase of transactionVersionBlockCases) {
    const blob = Buffer.from(testCase.blob, "hex");
    const converted = blocktemplate.convert_blob(blob, testCase.blobType);
    const blockId = blocktemplate.get_block_id(blob, testCase.blobType);

    assert(converted.length > 0, `${testCase.name} converted`);
    assert.strictEqual(blockId.length, 32, `${testCase.name} block id length`);
    if (testCase.expectedBlockId) {
      assert.strictEqual(blockId.toString("hex"), testCase.expectedBlockId, `${testCase.name} block id`);
    }
  }
});

const unsupportedTransactionVersionMutationCases = [
  { name: "xmr_v2_height_2000000", txVersionOffset: 43, unsupportedVersion: 3 },
  { name: "bloc_existing_fixture", txVersionOffset: 43, unsupportedVersion: 3 },
  { name: "ryo_v3_height_1000000", txVersionOffset: 43, unsupportedVersion: 4 },
  { name: "msr_existing_fixture", txVersionOffset: 43, unsupportedVersion: 3 },
  { name: "xmv_existing_fixture", txVersionOffset: 179, unsupportedVersion: 3 },
  { name: "zeph_v3_height_790000", txVersionOffset: 187, unsupportedVersion: 4 },
  { name: "xla_v2_height_1000000", txVersionOffset: 107, unsupportedVersion: 3 },
  { name: "sal_v5_height_500000", txVersionOffset: 43, unsupportedVersion: 6 },
  { name: "arq_v3_height_1957265", txVersionOffset: 43, unsupportedVersion: 4 }
];

test("cryptonote parser rejects unsupported transaction versions in real block blobs", () => {
  for (const mutationCase of unsupportedTransactionVersionMutationCases) {
    const testCase = findTransactionVersionBlockCase(mutationCase.name);
    const blob = Buffer.from(testCase.blob, "hex");

    assert.strictEqual(blob[mutationCase.txVersionOffset], testCase.txVersion, mutationCase.name);
    blob[mutationCase.txVersionOffset] = mutationCase.unsupportedVersion;

    assert.throws(
      () => blocktemplate.convert_blob(blob, testCase.blobType),
      /Failed to parse block/,
      `${testCase.name} v${mutationCase.unsupportedVersion} convert_blob`
    );
    assert.throws(
      () => blocktemplate.get_block_id(blob, testCase.blobType),
      /Failed to parse block/,
      `${testCase.name} v${mutationCase.unsupportedVersion} get_block_id`
    );
  }
});


test("convert_blob rejects removed coin-specific blob types", () => {
  const blob = Buffer.from(cases[0].blob, "hex");
  const removedBlobTypes = [2, 3, 5, 7, 9, 10, 11, 12];

  for (const blobType of removedBlobTypes) {
    assert.throws(
      () => blocktemplate.convert_blob(blob, blobType),
      /Unsupported blob type/
    );
  }
});

test("cryptonote parser rejects unsupported future transaction versions", () => {
  const xmrCase = cases.find((testCase) => testCase.name === "xmr");
  const blob = Buffer.from(xmrCase.blob, "hex");
  const minerTxVersionOffset = 43;

  assert.strictEqual(blob[minerTxVersionOffset], 2);
  blob[minerTxVersionOffset] = 3;

  assert.throws(
    () => blocktemplate.convert_blob(blob, xmrCase.variant),
    /Failed to parse block/
  );
  assert.throws(
    () => blocktemplate.get_block_id(blob, xmrCase.variant),
    /Failed to parse block/
  );
});

test("native methods reject non-buffer arguments without aborting", () => {
  const buffer = Buffer.alloc(4);

  assert.throws(
    () => blocktemplate.convert_blob(null),
    /Argument should be a buffer object/
  );
  assert.throws(
    () => blocktemplate.get_block_id(undefined),
    /Argument should be a buffer object/
  );
  assert.throws(
    () => blocktemplate.construct_block_blob(buffer, null),
    /Both arguments should be buffer objects/
  );
  assert.throws(
    () => blocktemplate.address_decode(null),
    /Argument should be a buffer object/
  );
  assert.throws(
    () => blocktemplate.address_decode_integrated(undefined),
    /Argument should be a buffer object/
  );
});

test("legacy merged-mining constructors are unsupported", () => {
  const buffer = Buffer.alloc(1);

  assert.throws(
    () => blocktemplate.construct_mm_parent_block_blob(buffer, 0, buffer),
    /Merged mining block construction is unsupported/
  );
  assert.throws(
    () => blocktemplate.construct_mm_child_block_blob(buffer, 0, buffer),
    /Merged mining block construction is unsupported/
  );
});

test("construct_block_blob validates Cuckoo cycle arguments", () => {
  const xmvCase = cases.find((testCase) => testCase.name === "xmv");
  const blob = Buffer.from(xmvCase.blob, "hex");
  const nonce = Buffer.alloc(4);
  const sparseCycle = new Array(32).fill(0);
  delete sparseCycle[0];
  const nonIntegerCycle = new Array(32).fill(0);
  nonIntegerCycle[0] = Infinity;

  assert.throws(
    () => blocktemplate.construct_block_blob(blob, nonce, 8, {}),
    /Cycle argument should be an array/
  );
  assert.throws(
    () => blocktemplate.construct_block_blob(blob, nonce, 8, []),
    /Cycle argument has invalid length/
  );
  assert.throws(
    () => blocktemplate.construct_block_blob(blob, nonce, 8, sparseCycle),
    /Cycle argument contains missing entries/
  );
  assert.throws(
    () => blocktemplate.construct_block_blob(blob, nonce, 8, nonIntegerCycle),
    /Cycle entries should be unsigned 32-bit integers/
  );
});

const salV11BlockIdCases = [
  {
    name: "sal_v11_create_token",
    blob: "0202959aef3a424242424242424242424242424242424242424242424242424242424242424217171717050001ff0000000100000509000000092a011111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233445566778899aabbccddeeff1020304050600353414c03544f4b070103544f4b0101c0843d0309546f6b656e697a65641d68747470733a2f2f6578616d706c652e696e76616c69642f746f6b656eabababababababababababababababababababababababababababababababab00",
    expected: "63266330e9fe8498f76b69350ff471fcfbdf1bf241698ea8a44f84cf95c7e95a"
  },
  {
    name: "sal_v11_rollup",
    blob: "0202959aef3a424242424242424242424242424242424242424242424242424242424242424229292929050001ff000000010000050d0000000a009191919191919191919191919191919191919191919191919191919191919191929292929292929292929292929292929292929292929292929292929292929203544f4b03544f4b009393939393939393010194949494949494949494949494949494949494949494949494949494949494949595959595959595959595959595959595959595959595959595959595959595c0c40700",
    expected: "2463cda5fa5f316894e29aa0f28352c64a92d0c22dae78599247369ca8fe288b"
  }
];

for (const testCase of salV11BlockIdCases) {
  test(`get_block_id ${testCase.name}`, () => {
    const actual = blocktemplate
      .get_block_id(Buffer.from(testCase.blob, "hex"), 15)
      .toString("hex");

    assert.strictEqual(actual, testCase.expected);
  });
}

test("convertRtmBlob handles RTM coinbase payload", () => {
  const blob = "000000205e54ede158d2cd4cd4dddb7f1e74316f52ce631a6d2f738c44da85cb0d13c2090000000000000000000000000000000000000000000000000000000000000000c5d2d56946a8041d000000000403000500010000000000000000000000000000000000000000000000000000000000000000ffffffff29032f191404c6d2d569110000001fabb38103cccccccccccccccccc0d2f6e6f64655374726174756d2f0000000003d8a14f9b150000001976a91463c99e48bd65b7ccbf9cef94bcced811a957778d88ac76e8d366050000001976a914cc36a8de36f6ff61dbfb798982e8b47354ad4e0e88acea9e6a06510000001976a914cf9e499affe93cb6ee344dd77c59e86ffb44814288ac000000004602002f191400ea558e624b4384efcb2621f0ed60a843a83929662c05af4602715b9475f3babcc6f0dea7b1209096e0958bc324f7f21ded775357853361d6be8b9ab0ca7ac9e90200000005adb00b1fb6a2a98396aa8cd62746a326f2cf81ad02e0061ed413c849a11d4f3d020000006a47304402203dbe7f5404e2b01e11d0219ca5833322eafbf6507345c75144e7e4fd776ccbaf022048ddcfdc26e5fdf8c2a1126887e5b42a9ff3e0672e826fd65ed941ab8e3b71a10121036c910a4671c2ab1c70863f22b573021e7f250304afbac1e8680d20616689b0f0feffffffb6785ef17e2da0df4fb442e037659d56d1f1fdabb2c0163bda09793b60bf623f020000006a4730440220193489a943c0e0379d9ed1c4aa10343b39c8637534d6ae85bbba5a2385f7a489022029b7306d1040f716090bff92f32b295a43003849842945a0b977a7c745d1395d0121036c910a4671c2ab1c70863f22b573021e7f250304afbac1e8680d20616689b0f0feffffff5e56a6824ff73497b7ea82d6a660817f8542942bbe8a7b0e73addd0e82c971b5020000006a47304402204065e73c908bdb43b850b67bd576b10236676bd1bd963384aaadf2b24f5961bc022005b5180adc5d3a320192d04c54e0062ae82ddd076f19489f00e2f41f13ca61350121036c910a4671c2ab1c70863f22b573021e7f250304afbac1e8680d20616689b0f0feffffffd0894a44e788c1151a259c9c21bed91d5e24d18ece2bf464823c534e2c74bcbb020000006a473044022069eb16418ef4950a42c779aa3af60bbf0ee77eff50c0862441c24c9c7bd5ad90022008624f02d94ac7d6fed4166b4c1645cb75b53f97f7df9f7a6f4a8c45aa171b440121036c910a4671c2ab1c70863f22b573021e7f250304afbac1e8680d20616689b0f0feffffffbe5a61ffa9fd588609bed0a0760ce1f07c8901b507a6e5297a0479b6651368c7020000006a47304402205021e25cac874ed6a7a6270348bf758e752e2e6484e6c6b7f72e7c02b31cae5a02200ebcc8c23575b6d02706c9b2c18d026f9c8d7bf8fcc5031de5c4249492c191960121036c910a4671c2ab1c70863f22b573021e7f250304afbac1e8680d20616689b0f0feffffff0219054c00000000001976a9145afb49fe4f0ae10d76ea67f5a54f340d5cde6f8988ac59f0c81f950100001976a9140ad191f6945efae4c376e25992b406913de9c67e88ac2d19140002000000027ba39664e381f9c7edd3b1684f691011b6653d284387c36ea65a168a42146b55000000006a4730440220715a184ec2a48ec4037dea4f000957d9f26e18820795c61027ec5a58b069035502207b918386846ad19dd5e44c42774e600b8b5ba27ae4689eb00cabeffbee72efae012103a9749d3fd79af7341f122e5eacdbd16222187aad0a88069e8775500109c0a886feffffff664f7f6e3cce9dc412179b1efeb9a5b59376e972ef39a93d7886cd1dc045acec0a0000006a473044022040dfaf4ecf0a894624425ba67663579fb631b21d663747e353c4acf2fdd7db3a022020f073b96181d38d86b43a5ab1538651d83c727a64a145a1a7511f77165d0e670121037d4f5bd98cda2779d1761183e53856341d11f3750dce439e77bbc027552931e3feffffff0d704e546a000000001976a914aee9ec8003c817dd49ec37942834af1daa7de66d88ac101238d2000000001976a914a700ce387da9e2355f0ce93def61a8196336700888aca048a7e7000000001976a914f75e45feebd9159cd2c6ebcc1913b602a4a6f74f88ac404c4c35010000001976a91416f3a3e1b5ccd013e752e5c43f3178068da6f88a88acd58e3bf5010000001976a91427397f3f7248d901bf2c2280dca044f97ed5e8d088ace0db6b49020000001976a914ab913b41894d6f67a06cbc114a469236180d4da888ace0651a32040000001976a91421454b0c23d041c8f1fa4f8c27958424b0c2948088ace0c0518b040000001976a9143e3ab78411e54f976f317e00f2e373d413e1090288aca05b3af2040000001976a91448361ca62b2756b4fa38b4d71e08e216785b5dc588aca084f81c070000001976a914e546b5f4c61c111ea2634faf389a278a4351fd7388ac30b338ac0a0000001976a91491cf402b8b9c7e75ecb78fda624ad1c44d30c01188ac608bf4c70c0000001976a91489e226c21b1397b9337f6baf389c2f8b0c19d04588acb05552f8270000001976a914a4310a3bbd82a15fda615bf73d5c422b9945d4d988ac2d19140002000000023605b314584781869ae2a96edd49f93892b8aa4cf74f69f74ebefed85ba84a71000000006b483045022100c6c19169e3a62561d275d95c3543541e2426d24760027a95042537270207693d02206ee697bc62edcfd6ef60a13b0b7ba8c2d48af0938e42d7c87cf39b7529e7c659012103879c1a9bb610d7d9d3c37dc6e9532f630e8ea38dbf29c7bbcd77ce72c56cecbcfeffffff3605b314584781869ae2a96edd49f93892b8aa4cf74f69f74ebefed85ba84a71010000006b483045022100b4f8411e3ca96eed3cab83b94cc02918cf4a80ec89454f7c8a5c7435e89d6a41022067e8dd63ac026a728a3c4063a7343d366c85a00815562f941127c057b32066f60121037c9540e6aac773318aa8660937839386ec5f323ba4978b56cb239841275e1874feffffff02babc1000000000001976a91452718864f0c5f09299ded73577e54e53d7b51a4488acba48b549ae1700001976a9146667df0538a0f254ed0e12a2962a04548e5a95cc88ac2d191400";

  const actual = blocktemplateJs.convertRtmBlob(Buffer.from(blob, "hex")).toString("hex");

  assert.strictEqual(
    actual,
    "000000205e54ede158d2cd4cd4dddb7f1e74316f52ce631a6d2f738c44da85cb0d13c209179bf7e1e32068f0c4058d7fa31dcb51448baead21123aa600656e3c802c76cfc5d2d56946a8041d00000000"
  );
});

const rtmSpecialTxHex = "0300020001f189c058fc197826cec441160f8395be58f6934661c2f6054a067cd25a050749470000006a473044022001b0264312ef5f1c7f8c6843f31b625fc76c2e5848ded7ae8b94158b4166c831022045a093291ceb88adaf51d71e2329b95a6d6ac64a9fed32e85c9eecf317e3cf400121023b91003cc79ca481f3b54d2e55fb3a34cf25c7985a3c1d15ae8b2883d2488a45feffffff012ac89a3b000000001976a91426d6b7e9fc7dbbff032671e6428cb9fe5775cf1d88ac00000000b50100ace0340b5fc4ace3961a901b6855b4ddc041d558b64332ca4c72d74b084b02f100000000000000000000ffff4ebbb50227f200a03b94374a8f31ea85034739c37179fc99544bd35a3b4266d5ebc043a06df114839a7e28a7a7d608e8e4a0a7f6f9b904223f639ffa678fa40e9bd14c7e76bd07be2033e213ce8d558b9761baa2b62c4e06e740236a5ec15c6b61ba39a19d5bc6b813440a424976c0da7e7ecd47084f812f7c19381e76300da0d65189d36dc313";
const rtmQuorumCommitmentTxHex = `03000600000000000000fd0401${  "aa".repeat(260)}`;
const rtmNormalTxHex = `0200000001${  "11".repeat(32)  }000000000151feffffff01e803000000000000015100000000`;

function hash256(buffer) {
  const first = crypto.createHash("sha256").update(buffer).digest();
  return crypto.createHash("sha256").update(first).digest();
}

function hash256_3(buffer) {
  const first = crypto.createHash("sha3-256").update(buffer).digest();
  return crypto.createHash("sha3-256").update(first).digest();
}

function buildEmptyRtmSpecialTx(type, payload = "") {
  const txVersion = Buffer.alloc(4);
  txVersion.writeInt32LE(3 | (type << 16));
  const payloadLength = Buffer.from([payload.length / 2]);
  return Buffer.concat([
    txVersion,
    Buffer.from("000000000000", "hex"),
    payloadLength,
    Buffer.from(payload, "hex")
  ]).toString("hex");
}

function buildRtmTemplate(transactions, overrides = {}) {
  return rtm.RtmBlockTemplate(Object.assign({
    previousblockhash: "00".repeat(32),
    version: 0x20000000,
    curtime: 1710000000,
    bits: "1d00ffff",
    target: "00000000ffff0000000000000000000000000000000000000000000000000000",
    height: 1,
    coinbaseaux: { flags: "" },
    coinbasevalue: 5000000000,
    transactions
  }, overrides), "RUCyaEZxQu3Eure73XPQ57si813RYAMQKC");
}

test("RtmBlockTemplate rejects invalid RTM coinbase dev rewards", () => {
  assert.throws(() => buildRtmTemplate([], {
    coinbasedevreward: { value: 100000000, scriptpubkey: "zz" }
  }), /Invalid coinbase dev reward/);
});

test("RtmBlockTemplate caps daemon transactions so the encoded total stays within the merkle cap", () => {
  // 5000 daemon txs + the coinbase = 5001 encoded, which exceeds the consumer's 5000 total-tx merkle
  // cap (the prior off-by-one: producer allowed 5000 daemon -> consumer rejected -> lost block).
  // The producer must now reject at 5000 (cap is 4999 daemon). The gate is a pure .length check,
  // so dummy entries are sufficient (it throws before any tx is parsed).
  const tooMany = Array.from({ length: 5000 }, () => ({ data: "00" }));
  assert.throws(() => buildRtmTemplate(tooMany), /Too many RTM transactions/);
});

test("RtmBlockTemplate rejects nBits that is not exactly 4 bytes", () => {
  // a >4-byte bits would silently corrupt the header on the 4-byte byte-swap; require exactly 4 bytes
  assert.throws(() => buildRtmTemplate([], { bits: "1d00ffffaa" }), /Invalid RTM bits/);
});

test("RtmBlockTemplate rejects overlong payout addresses without echoing input", () => {
  const payee = `R${  "A".repeat(256)}`;
  assert.throws(
    () => buildRtmTemplate([], {
      smartnode: { amount: 1, payee }
    }),
    (err) => {
      assert.match(err.message, /Invalid address length/);
      assert.equal(err.message.includes(payee), false);
      return true;
    }
  );
});

test("RtmBlockTemplate limits transaction count", () => {
  assert.throws(
    () => buildRtmTemplate(new Array(5001).fill({ version: 1, data: "" })),
    /Too many RTM transactions/
  );
});

test("RtmBlockTemplate logs skipped RTM transactions without echoing data", () => {
  const txData = "aa".repeat(1024);
  const originalConsoleError = console.error;
  const logs = [];
  console.error = (message) => logs.push(String(message));

  try {
    buildRtmTemplate([{ version: 2, data: txData }]);
  } finally {
    console.error = originalConsoleError;
  }

  assert.equal(logs.length, 1);
  assert.match(logs[0], /1024 byte transaction/);
  assert.equal(logs[0].includes(txData), false);
});

test("readTransaction handles RTM quorum commitment payload boundaries", () => {
  const txBuffer = Buffer.from(rtmQuorumCommitmentTxHex, "hex");
  const parsed = rtm.readTransaction(txBuffer, 0, true);

  assert.equal(parsed.offset, txBuffer.length);
  assert.equal(parsed.transaction.version, 0x00060003);
  assert.equal(parsed.transaction.payload.length, 260);
  assert.equal(parsed.transaction.__toBuffer().toString("hex"), rtmQuorumCommitmentTxHex);
});

test("readTransaction accepts known RTM special transaction types", () => {
  for (const type of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) {
    const txHex = buildEmptyRtmSpecialTx(type);
    const parsed = rtm.readTransaction(Buffer.from(txHex, "hex"), 0, true);

    assert.equal(parsed.offset, txHex.length / 2);
    assert.equal(parsed.transaction.version, 3 | (type << 16));
    assert.equal(parsed.transaction.payload.length, 0);
  }
});

test("RtmBlockTemplate includes special transaction payloads", () => {
  const actual = rtm.RtmBlockTemplate({
    previousblockhash: "00".repeat(32),
    version: 0x20000000,
    curtime: 1710000000,
    bits: "1d00ffff",
    target: "00000000ffff0000000000000000000000000000000000000000000000000000",
    height: 1,
    coinbaseaux: { flags: "" },
    coinbasevalue: 5000000000,
    transactions: [{ version: 3, data: rtmSpecialTxHex }]
  }, "RUCyaEZxQu3Eure73XPQ57si813RYAMQKC");

  assert.equal(actual.blocktemplate_blob.slice(160, 162), "02");
  assert.ok(actual.blocktemplate_blob.endsWith(rtmSpecialTxHex));
});

test("convertRtmBlob handles RTM special payloads before later transactions", () => {
  const originalDateNow = Date.now;
  Date.now = () => 1710000000000;

  try {
    const template = rtm.RtmBlockTemplate({
      previousblockhash: "00".repeat(32),
      version: 0x20000000,
      curtime: 1710000000,
      bits: "1d00ffff",
      target: "00000000ffff0000000000000000000000000000000000000000000000000000",
      height: 1,
      coinbaseaux: { flags: "" },
      coinbasevalue: 5000000000,
      coinbase_payload: "abcd",
      transactions: [
        { version: 3, data: rtmSpecialTxHex },
        { version: 2, data: rtmNormalTxHex }
      ]
    }, "RUCyaEZxQu3Eure73XPQ57si813RYAMQKC");

    const actual = blocktemplateJs.convertRtmBlob(Buffer.from(template.blocktemplate_blob, "hex")).toString("hex");

    assert.strictEqual(
      actual,
      "00000020000000000000000000000000000000000000000000000000000000000000000038947a729925a67a53bfdd9d79cea1acd9dc18aa4e5dac9303e4f45e93bd8e6f8087ec65ffff001d00000000"
    );
  } finally {
    Date.now = originalDateNow;
  }
});

test("convertRtmBlob handles RTM quorum commitments before later transactions", () => {
  const originalDateNow = Date.now;
  Date.now = () => 1710000000000;

  try {
    const template = buildRtmTemplate([
      { version: 3, data: rtmQuorumCommitmentTxHex },
      { version: 2, data: rtmNormalTxHex }
    ]);

    const actual = blocktemplateJs.convertRtmBlob(Buffer.from(template.blocktemplate_blob, "hex")).toString("hex");

    assert.strictEqual(
      actual,
      "0000002000000000000000000000000000000000000000000000000000000000000000005e9f869834b9229fd351eee958fc041ce22d5483efd51cf21876a6733542b1148087ec65ffff001d00000000"
    );
  } finally {
    Date.now = originalDateNow;
  }
});

test("convertRtmBlob recovers RTM special transaction tail before next transaction", () => {
  const txType6WithPayload329 = Buffer.concat([
    Buffer.from("03000600000000000000fd4901", "hex"),
    Buffer.alloc(329, 0)
  ]);
  const nextType6 = Buffer.from(buildEmptyRtmSpecialTx(6), "hex");
  const blob = Buffer.concat([
    Buffer.alloc(80, 0),
    Buffer.from("02", "hex"),
    txType6WithPayload329,
    Buffer.alloc(8, 0),
    nextType6
  ]);

  const actual = blocktemplateJs.convertRtmBlob(blob).toString("hex");

  assert.strictEqual(
    actual,
    "000000000000000000000000000000000000000000000000000000000000000000000000c3768d8beb2782fc90da561181d0c236f9620cf3714bb4f9c3e379516bb435f6000000000000000000000000"
  );
});

test("convertRtmBlob rejects malformed RTM template data", () => {
  const tooManyTransactions = Buffer.concat([
    Buffer.alloc(80, 0),
    Buffer.from("fd8913", "hex")
  ]);
  assert.throws(
    () => blocktemplateJs.convertRtmBlob(tooManyTransactions),
    /Invalid transaction count/
  );
  assert.throws(
    () => blocktemplateJs.constructNewRtmBlob(Buffer.from(tooManyTransactions), Buffer.from("11223344", "hex")),
    /Invalid transaction count/
  );
});

test("convertRtmBlob rejects unconsumed bytes after declared RTM transactions", () => {
  const tx = Buffer.from(buildEmptyRtmSpecialTx(6), "hex");
  const blob = Buffer.concat([
    Buffer.alloc(80, 0),
    Buffer.from("01", "hex"),
    tx,
    Buffer.from("00", "hex")
  ]);

  assert.throws(
    () => blocktemplateJs.convertRtmBlob(blob),
    /Unexpected data after block template transactions/
  );
});

test("convertRtmBlob handles RTM special coinbase without daemon payload", () => {
  const originalDateNow = Date.now;
  Date.now = () => 1710000000000;

  try {
    const template = buildRtmTemplate([
      { version: 3, data: rtmSpecialTxHex },
      { version: 2, data: rtmNormalTxHex }
    ]);

    const actual = blocktemplateJs.convertRtmBlob(Buffer.from(template.blocktemplate_blob, "hex")).toString("hex");

    assert.strictEqual(
      actual,
      "000000200000000000000000000000000000000000000000000000000000000000000000dcfc2be89415b5d826ac3b4a1ac1a4db2a7ad8578e63f0ffb4678978f5b8a2958087ec65ffff001d00000000"
    );
  } finally {
    Date.now = originalDateNow;
  }
});

test("convertRtmBlob uses txid merkle root for RTM witness coinbase", () => {
  const originalDateNow = Date.now;
  Date.now = () => 1710000000000;

  try {
    const template = buildRtmTemplate([], {
      default_witness_commitment: `6a24aa21a9ed${  "00".repeat(32)}`
    });
    const blob = Buffer.from(template.blocktemplate_blob, "hex");
    const header = blocktemplateJs.convertRtmBlob(blob);

    let offset = 80;
    const transactionCount = varuint.decode(blob, offset);
    offset += varuint.decode.bytes;
    assert.equal(transactionCount, 1);

    const parsed = rtm.readTransaction(blob, offset, true);
    const txidMerkleRoot = hash256(parsed.transaction.__toBuffer(undefined, undefined, false));
    const witnessCommitmentRoot = hash256(Buffer.concat([
      Buffer.alloc(32, 0),
      parsed.transaction.ins[0].witness[0]
    ]));

    assert.equal(header.slice(36, 68).toString("hex"), txidMerkleRoot.toString("hex"));
    assert.notEqual(header.slice(36, 68).toString("hex"), witnessCommitmentRoot.toString("hex"));
  } finally {
    Date.now = originalDateNow;
  }
});

test("constructNewKcnBlob uses SHA3 merkle branch hashing", () => {
  const tx = Buffer.from(rtmNormalTxHex, "hex");
  const blob = Buffer.concat([
    Buffer.alloc(80, 0),
    Buffer.from("02", "hex"),
    tx,
    tx
  ]);
  const actual = blocktemplateJs.constructNewKcnBlob(blob, Buffer.from("11223344", "hex"));
  const txHash = hash256_3(tx);
  const expectedMerkleRoot = hash256_3(Buffer.concat([txHash, txHash]));
  const bitcoinStyleMerkleRoot = hash256(Buffer.concat([txHash, txHash]));

  assert.equal(actual.slice(36, 68).toString("hex"), expectedMerkleRoot.toString("hex"));
  assert.notEqual(actual.slice(36, 68).toString("hex"), bitcoinStyleMerkleRoot.toString("hex"));
});

test("RavenBlockTemplate includes daemon-supplied CLORE community payout", () => {
  const poolAddress = "RUCyaEZxQu3Eure73XPQ57si813RYAMQKC";
  const communityAddress = poolAddress;
  const template = blocktemplateJs.RavenBlockTemplate({
    height: 1,
    bits: "1d00ffff",
    curtime: 1710000000,
    previousblockhash: "00".repeat(32),
    version: 0x20000000,
    coinbasevalue: 5000000000,
    target: "00000000ffff0000000000000000000000000000000000000000000000000000",
    transactions: [],
    CommunityAutonomousAddress: communityAddress,
    CommunityAutonomousValue: 1250000000
  }, poolAddress);
  const blob = Buffer.from(template.blocktemplate_blob, "hex");
  let offset = 80 + 8 + 32;
  const txCount = varuint.decode(blob, offset);
  offset += varuint.decode.bytes;
  const coinbase = bitcoin.Transaction.fromBuffer(blob.slice(offset), true, false);

  assert.equal(txCount, 1);
  assert.deepEqual(coinbase.outs.map((output) => output.value), [5000000000, 1250000000]);
});

test("block template difficulty rejects invalid targets and uses exact scaled Raven/RTM arithmetic", () => {
  const ravenTemplate = blocktemplateJs.RavenBlockTemplate({
    height: 1,
    bits: "1d00ffff",
    curtime: 1710000000,
    previousblockhash: "00".repeat(32),
    version: 0x20000000,
    coinbasevalue: 5000000000,
    target: "000000007f800000000000000000000000000000000000000000000000000001",
    transactions: []
  }, "RUCyaEZxQu3Eure73XPQ57si813RYAMQKC");

  assert.equal(ravenTemplate.difficulty, 1.999999999);
  assert.equal(buildRtmTemplate([], {
    target: "8000000000000000000000000000000000000000000000000000000000000000"
  }).difficulty, 1.999999999);
  assert.throws(
    () => blocktemplateJs.RavenBlockTemplate({
      height: 1,
      bits: "1d00ffff",
      curtime: 1710000000,
      previousblockhash: "00".repeat(32),
      version: 0x20000000,
      coinbasevalue: 5000000000,
      target: "00",
      transactions: []
    }, "RUCyaEZxQu3Eure73XPQ57si813RYAMQKC"),
    /Invalid Raven target/
  );
  assert.throws(
    () => blocktemplateJs.EthBlockTemplate([`0x${  "11".repeat(32)}`, `0x${  "22".repeat(32)}`, "0x0", "1"]),
    /Invalid ETH target/
  );
  assert.throws(
    () => blocktemplateJs.ErgBlockTemplate({ msg: "11", pk: "22", b: "0", h: "1" }),
    /Invalid ERG target/
  );
  assert.throws(
    () => buildRtmTemplate([], { target: "00" }),
    /Invalid RTM target/
  );
});
