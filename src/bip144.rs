
/**
 *  Serialization:
 
  Field Size	Name	Type	Description
  4	version	int32_t	Transaction data format version
  1	marker	char	Must be zero
  1	flag	char	Must be nonzero
  1+	txin_count	var_int	Number of transaction inputs
  41+	txins	txin[]	A list of one or more transaction inputs
  1+	txout_count	var_int	Number of transaction outputs
  9+	txouts	txouts[]	A list of one or more transaction outputs
  1+	script_witnesses	script_witnesses[]	The witness structure as a serialized byte array
  4	lock_time	uint32_t	The block number or timestamp until which the transaction is locked
 */
pub fn serialize() {

}

pub fn encode_vout(vout: Vout) {
  let amount_bytes_le = vout.value.to_le_bytes();
  let script_size: usize = vout.script_pub_key.as_bytes().len();
  let script_size_bytes = script_size.to_le_bytes();
}