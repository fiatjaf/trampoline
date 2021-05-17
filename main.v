import crypto.sha256
import x.json2
import fiatjaf.vlightning

fn main() {
	mut plugin := vlightning.Plugin{
		name: 'trampoline'
		version: '0.1'
		rpcmethods: map{
			'sendtrampoline': vlightning.RPCMethod{
				usage: 'route payment_hash [label] [msatoshi] [bolt11] [payment_secret] [partid]'
				description: 'like sendpay, but using trampoline routes'
				long_description: 'instead of sending the full route, send just the route until the trampoline node desired then another special trampoline hop until the destination'
				handler: sendtrampoline
			}
		}
		dynamic: true
	}

	plugin.initialize()
}

fn sendtrampoline(p vlightning.Plugin, params json2.Any) ?json2.Any {
	mparams := params.as_map()
	route := mparams['route'].arr()

	/*
	route is expected to be in this format:
    [
      {
         "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
         "channel": "683194x1679x1",
         "msatoshi": 10015222,
         "delay": 153
      },
      {
         "id": "02c16cca44562b590dd279c942200bdccfd4f990c3a69fad620c10ef2f8228eaff",
         "channel": "677702x1820x1",
         "msatoshi": 10015000,
         "delay": 120
      },
      {
         "style": "trampoline",
         "id": "02845cc3fb26c21575eba0fded926233f55b67b80180e01eead18aae848abc679f",
         "msatoshi": 10009000,
         "delay": 80
      },
      {
         "style": "trampoline",
         "id": "02868e12f320073cad0c2959c42559fbcfd1aa326fcb943492ed7f02c9820aa399",
         "msatoshi": 10000000,
         "delay": 40
      }
    ]
    i.e., some hops in the beginning,
          then any number of trampoline hops including the last.
	*/

	if route.len < 2 {
		return error('route must have at least 2 hops')
	}

	r_nodeinfo := p.client.call('getinfo') or {
		return error('error getting own node info: $err.msg')
	}

	our_pubkey := r_nodeinfo.as_map()['id']
	r_blockchaininfo := p.client.call('getchaininfo') or {
		return error('error getting blockchain info: $err.msg')
	}
	current_block := r_blockchaininfo.as_map()['headercount'].int()

	mut first_hop := map[string]json2.Any{}
	destination := route[route.len - 1].as_map()['id']

	payment_hash := mparams['payment_hash']
	label := mparams['label']
	bolt11 := mparams['bolt11']
	partid := mparams['partid']
	payment_secret := mparams['payment_secret'].str()
	invoice := p.client.call('decodepay', bolt11.str()) or { json2.Null{} }

	mut payment_secret_32 := [32]byte{}
	if payment_secret != '' {
		hex_to_32(mut payment_secret_32, payment_secret)
	} else if invoice is map[string]json2.Any {
		if invoice['payment_secret'] is string {
			hex_to_32(mut payment_secret_32, payment_secret.str())
		} else {
			return error('the provided invoice does not have a payment_secret')
		}
	} else {
		return error('missing payment_secret and no bolt11 invoice provided')
	}

	mut msatoshi := mparams['msatoshi']
	if !(msatoshi is string) && !(msatoshi is int) {
		msatoshi = route[route.len - 1].as_map()['msatoshi']
	}

	// extract the trampoline hops so we can turn them into a special onion later.
	mut actual_route := []json2.Any{}
	mut trampolines := []json2.Any{}
	for i, _ in route {
		mut this_hop := route[i].as_map()
		if this_hop['style'].str() == 'legacy' {
			return error('legacy onion payloads are not supported')
		}

		if this_hop['style'].str() == 'trampoline' {
			if actual_route.len == 0 {
				return error("route doesn't contain non-trampoline hops")
			}

			trampolines << this_hop

			// add stuff to the last non-trampoline hop
			mut last_actual_hop := actual_route[actual_route.len - 1].as_map()
			last_actual_hop['msatoshi'] = last_actual_hop['msatoshi'].int() +
				this_hop['msatoshi'].int()
			last_actual_hop['delay'] = last_actual_hop['delay'].int() + this_hop['delay'].int()
			actual_route[actual_route.len - 1] = last_actual_hop
		} else {
			actual_route << this_hop
		}
	}

	if trampolines.len == 0 {
		return error("route doesn't contain trampolines, use sendpay directly")
	}

	// actually make the TLV payloads
	mut onionhops := []json2.Any{}
	for i, _ in actual_route {
		mut this_hop := actual_route[i].as_map()
		mut onionhop := map{
			'pubkey': this_hop['id']
		}

		is_final := i == actual_route.len - 1

		mut payload := vlightning.Writer{}
		next_hop := match is_final {
			false { actual_route[i + 1].as_map() }
			true { this_hop }
		}

		// all hops
		payload.write_bigsize(vlightning.tlv_amount_to_forward) // T
		outgoing_msat := vlightning.encode_tu64(u64(next_hop['msatoshi'].int()))
		payload.write_bigsize(outgoing_msat.len) // L
		payload.write_bytes(outgoing_msat) // V

		payload.write_bigsize(vlightning.tlv_outgoing_cltv) // T
		outgoing_cltv := vlightning.encode_tu32(u32(current_block + next_hop['delay'].int()))
		payload.write_bigsize(outgoing_cltv.len) // L
		payload.write_bytes(outgoing_cltv) // V

		if !is_final {
			// intermediate hop
			payload.write_bigsize(vlightning.tlv_outgoing_channel_id) // T
			payload.write_bigsize(8) // L
			scid := next_hop['channel'].str()

			scid_u64 := vlightning.parse_short_channel_id(scid) ?
			payload.write_u64(scid_u64) // V
		} else {
			// final hop, will contain a fake secret and a trampoline onion
			payload.write_bigsize(vlightning.tlv_payment_data) // T
			mut fake_secret := [32]byte{} // deterministic
			fake_secret_src := '${this_hop['id']}$our_pubkey$payment_hash'
			bytes_to_32(mut fake_secret, sha256.sum256(fake_secret_src.bytes()))
			msat_to_trampoline := vlightning.encode_tu64(u64(next_hop['msatoshi'].int()))
			payload.write_bigsize(32 + msat_to_trampoline.len) // L
			payload.write_32(fake_secret) // V
			payload.write_bytes(msat_to_trampoline) // V

			// make the trampoline onion
			mut trampoline_hops := []json2.Any{}
			for t, _ in trampolines {
				this_thop := trampolines[t].as_map()

				mut trampoline_hop := map{
					'pubkey': this_thop['id']
				}

				is_tfinal := t == trampolines.len - 1

				mut tpayload := vlightning.Writer{}
				next_thop := match is_tfinal {
					false { trampolines[t + 1].as_map() }
					true { this_thop }
				}

				// all hops
				tpayload.write_bigsize(vlightning.tlv_amount_to_forward) // T
				toutgoing_msat := vlightning.encode_tu64(u64(next_thop['msatoshi'].int()))
				tpayload.write_bigsize(toutgoing_msat.len) // L
				tpayload.write_bytes(toutgoing_msat) // V

				tpayload.write_bigsize(vlightning.tlv_outgoing_cltv) // T
				toutgoing_cltv := vlightning.encode_tu32(u32(current_block +
					next_thop['delay'].int()))
				tpayload.write_bigsize(toutgoing_cltv.len) // L
				tpayload.write_bytes(toutgoing_cltv) // V

				if is_tfinal {
					// final hop, include secret and invoice stuff
					tpayload.write_bigsize(vlightning.tlv_payment_data) // T
					final_msatoshi_tu64 := vlightning.encode_tu64(u64(msatoshi.int()))
					tpayload.write_bigsize(32 + final_msatoshi_tu64.len) // L
					tpayload.write_32(payment_secret_32)
					tpayload.write_bytes(final_msatoshi_tu64)

					if invoice is map[string]json2.Any {
						tpayload.write_bigsize(vlightning.tlv_invoice_features) // T
						tpayload.write_bigsize(8) // L
						invoice_features := hex_to_bytes(invoice['features'].str())
						tpayload.write_bytes(invoice_features) // V
					}
				}

				// again all hops (tlv ordering matters)
				tpayload.write_bigsize(vlightning.tlv_outgoing_node_id) // T
				outgoing_node_id := hex_to_bytes(next_thop['id'].str())
				tpayload.write_bigsize(33) // L
				tpayload.write_bytes(outgoing_node_id) // V

				// TODO
				// if is_final {
				// 	// again only final (tlv ordering matters)
				// 	if invoice is map[string]json2.Any {
				// 		tpayload.write_bigsize(vlightning.tlv_invoice_routing_info) // T
				// 		invoice_routing_info := ''
				// 		tpayload.write_bigsize(invoice_routing_info.len) // L
				// 		tpayload.write_bytes(invoice_routing_info) // V
				// 	}
				// }

				trampoline_hop['payload'] = json2.Any(tpayload.buf.hex())
				trampoline_hops << trampoline_hop
			}

			r_tcreateonion := p.client.call('createonion', map{
				'hops':       json2.Any(trampoline_hops)
				'assocdata':  payment_hash
				'onion_size': json2.Any(400)
			}) or { return error('failed to create trampoline onion: $err.msg') }

			trampoline_onion := hex_to_bytes(r_tcreateonion.as_map()['onion'].str())

			payload.write_bigsize(vlightning.tlv_trampoline_onion) // T
			payload.write_bigsize(trampoline_onion.len) // L
			payload.write_bytes(trampoline_onion) // V
		}

		onionhop['payload'] = json2.Any(payload.buf.hex())
		onionhops << onionhop
	}

	r_createonion := p.client.call('createonion', onionhops, payment_hash) or {
		return error('failed to createonion: $err.msg')
	}

	first_hop['id'] = actual_route[0].as_map()['id']
	first_hop['amount_msat'] = '${actual_route[0].as_map()['msatoshi']}msat'
	first_hop['delay'] = actual_route[0].as_map()['delay']
	onion := r_createonion.as_map()['onion']
	shared_secrets := r_createonion.as_map()['shared_secrets']

	mut sendonion_params := map{
		'first_hop':      json2.Any(first_hop)
		'onion':          onion
		'shared_secrets': shared_secrets
		'payment_hash':   payment_hash
		'destination':    destination
		'msatoshi':       msatoshi
	}
	if partid is int || partid is string {
		sendonion_params['partid'] = partid
	}
	if label is string {
		sendonion_params['label'] = label
	}
	if bolt11 is string {
		sendonion_params['bolt11'] = bolt11
	}

	return p.client.call('sendonion', sendonion_params)
}
