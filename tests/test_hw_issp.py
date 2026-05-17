from hdd_toolkit.hw.issp import ISSPEngine, ISSPVector


def test_build_vector_wrmem():
    vec = ISSPEngine.build_vector(ISSPEngine.OPCODE_WRMEM, 0x00, 0x00)
    assert isinstance(vec, ISSPVector)
    assert vec.length == 22


def test_build_vector_opcode_field():
    vec = ISSPEngine.build_vector(ISSPEngine.OPCODE_WRREG, 0xF8, 0xAB)
    opcode = (vec.bits >> 18) & 0xF
    addr = (vec.bits >> 10) & 0xFF
    data = (vec.bits >> 2) & 0xFF
    assert opcode == ISSPEngine.OPCODE_WRREG
    assert addr == 0xF8
    assert data == 0xAB


def test_build_vector_rdmem():
    vec = ISSPEngine.build_vector(ISSPEngine.OPCODE_RDMEM, 0x10, 0x00)
    opcode = (vec.bits >> 18) & 0xF
    assert opcode == ISSPEngine.OPCODE_RDMEM


def test_entry_sequence():
    engine = ISSPEngine()
    vectors = engine.entry_sequence()
    assert isinstance(vectors, list)
    assert all(isinstance(v, ISSPVector) for v in vectors)


def test_write_reg_updates_sram():
    engine = ISSPEngine()
    vec = engine.write_reg(0xF8, 0x42)
    assert engine._sram[0xF8] == 0x42
    opcode = (vec.bits >> 18) & 0xF
    assert opcode == ISSPEngine.OPCODE_WRREG


def test_read_reg():
    engine = ISSPEngine()
    vec = engine.read_reg(0xF9)
    opcode = (vec.bits >> 18) & 0xF
    addr = (vec.bits >> 10) & 0xFF
    assert opcode == ISSPEngine.OPCODE_RDREG
    assert addr == 0xF9


def test_write_mem():
    engine = ISSPEngine()
    vec = engine.write_mem(0x00, 0xDE)
    assert engine._sram[0x00] == 0xDE
    opcode = (vec.bits >> 18) & 0xF
    assert opcode == ISSPEngine.OPCODE_WRMEM


def test_read_mem():
    engine = ISSPEngine()
    vec = engine.read_mem(0x10)
    opcode = (vec.bits >> 18) & 0xF
    assert opcode == ISSPEngine.OPCODE_RDMEM


def test_srom_call_three_vectors():
    engine = ISSPEngine()
    vectors = engine.srom_call(ISSPEngine.SROM_FN_CHECKSUM_SETUP)
    assert len(vectors) == 3
    addrs = [(v.bits >> 10) & 0xFF for v in vectors]
    assert ISSPEngine.PSOC_REG_KEY1 in addrs
    assert ISSPEngine.PSOC_REG_KEY2 in addrs
    assert ISSPEngine.PSOC_REG_SROM_PARAM in addrs


def test_checksum_setup_vectors():
    engine = ISSPEngine()
    vectors = engine.checksum_setup_vectors()
    assert len(vectors) == 3
    params = [(v.bits >> 2) & 0xFF for v in vectors]
    assert ISSPEngine.SROM_FN_CHECKSUM_SETUP in params


def test_read_security_data():
    engine = ISSPEngine()
    vectors = engine.read_security_data()
    assert len(vectors) > 3


def test_get_sram_snapshot():
    engine = ISSPEngine()
    engine.write_reg(0xF8, 0x11)
    engine.write_reg(0xF9, 0x22)
    snap = engine.get_sram_snapshot()
    assert snap[0xF8] == 0x11
    assert snap[0xF9] == 0x22


def test_sync_sequence():
    engine = ISSPEngine()
    vectors = engine.sync_sequence()
    assert isinstance(vectors, list)


def test_issp_vector_to_bytes():
    vec = ISSPVector(bits=0b1010101010101010101010, length=22)
    b = vec.to_bytes()
    assert isinstance(b, bytes)
    assert len(b) > 0


def test_issp_constants():
    assert ISSPEngine.PSOC_REG_KEY1 == 0xF8
    assert ISSPEngine.PSOC_REG_KEY2 == 0xF9
    assert ISSPEngine.PSOC_REG_SROM_PARAM == 0xFA
    assert ISSPEngine.PSOC_REG_TEMP == 0xF1
    assert ISSPEngine.SROM_FN_CHECKSUM_SETUP == 0x07
