-- create myproto protocol and fields

--VALID FOR COAP18

--FOR DEVELOPERS: Depending on how many options are used, it is important to change the definition of the option fields.(see line 53)
--Comment out the now active option fields and uncomment those important for your application. Remember to comment out line 80 and uncomment and change line 83 to add fields you've previously uncommented
require "bitstring" --bitstring needs a driver. Search for Coap dissector on github, a dissector for version 12 also has the right dll. Please remember to give credit to the developer.
    
local codeList = {
	[0]   = "Empty",
	[1]   = "GET",
	[2]   = "POST",
	[3]   = "PUT",
	[4]   = "DELETE",
	[65]  = "2.01 Created",
	[66]  = "2.02 Deleted",
	[67]  = "2.03 Valid",
	[68]  = "2.04 Changed",
	[69]  = "2.05 Content",
	[128] = "4.00 Bad Request",
	[129] = "4.01 Unauthorized",
	[130] = "4.02 Bad Option",
	[131] = "4.03 Forbidden",
	[132] = "4.04 Not Found",
	[133] = "4.05 Method Not Allowed",
	[134] = "4.06 Not Acceptable",
	[140] = "4.12 Precondition Failed",
	[141] = "4.13 Request Entity Too Large",
	[143] = "4.15 Unsupported Content-Format",
	[160] = "5.00 Internal Server Error",
	[161] = "5.01 Not Implemented",
	[162] = "5.02 Bad Gateway",
	[163] = "5.03 Service Unavailable",
	[164] = "5.04 Gateway Timeout",
	[165] = "5.05 Proxying Not Supported",
	[95] = "5.15 Acknowledge Without Data"
}
--D0016E specific: every ack has code ... 95. Why?

--definition of fields in CoAP message
p_CoAProtocol = Proto("CoAProtocol", "CoAP - version 18 tweaked by the monkeys at 1203")
--start of header field
local f_Ver = ProtoField.uint8("CoAProtocol.version", "Version", base.DEC, nil, 0xC0) 
local f_Type = ProtoField.uint8("CoAProtocol.Type", "Type", base.DEC,
		{ [0] = "CON", [1] = "NON", [2] = "ACK", [3] = "Reset" }, 0x30) 
local f_TKL = ProtoField.uint8("CoAProtocol.TKL", "Token length, bytes", base.DEC, nil, 0x0F)
local f_Code = ProtoField.uint8("CoAProtocol.Code", "Code", base.DEC, codeList)
local f_MsgID = ProtoField.uint16("CoAProtocol.MsgID", "Message ID", base.DEC)
--end of header, start of token field
local f_Token = ProtoField.uint64("CoAProtocol.Token", "Token", base.HEX)
--end of token, start of option field

--Options will only consist of: port number, "\dummydata" check wireshark captures  to get bits.
local f_option1 = ProtoField.uint16("CoAProtocol.option1", "Option 1, destination port number", FT_STRING)
local f_option2 = ProtoField.string("CoAProtocol.option2", "Option 2, point of transmission", string.char(base.DEC))

--Start option fields for a CoAP:
    --local f_option_if-match = ProtoField.Opaque("CoAProtocol.if-match", "IF_Match", OPAQUE) ---might not be necessary
    --local f_option_Uri-Host = ProtoField.string("CoAProtocol.Uri-Host", "Uri host", FT_STRING)
    --local f_option_ETag = ProtoField.Opaque("CoAProtocol.ETag", "ETag", OPAQUE)
    --local f_option_Uri-Port = ProtoField.uint16("CoAProtocol.Uri-Port", "Uri port", base.DEC)
    --local f_option_Location-Path = ProtoField.string("CoAProtocol.Location-Path", "Location path", FT_STRING)
    --local f_option_Uri-Path = ProtoField.string("CoAProtocol.Uri-Path", "Uri path", FT_STRING)
    --local f_option_Content-Format = ProtoField.uint16("CoAProtocol.Content-Format", "Content format", base.DEC) --check ietf draft for numeric values and their translations
    --local f_option_Max-Age = ProtoField.uint32("CoAProtocol.Max-Age", "Max age", base.DEC)
    --local f_option_Uri-Query = ProtoField.string("CoAProtocol.Uri-Query", "Uri query", FT_STRING)
    --local f_option_Accept = ProtoField.uint16("CoAProtocol.Accept", "Accept", base.DEC)
    --local f_option_Location-Query = ProtoField.string("CoAProtocol.Location-Query", "Location query", FT_STRING)
    --local f_option_Proxy-Uri = ProtoField.string("CoAProtocol.Proxy-Uri", "Proxy uri", FT_STRING)
    --local f_option_Proxy-Scheme = ProtoField.string("CoAProtocol.Proxy-Scheme", "Proxy scheme", FT_STRING)
    --local f_option_Size1 = ProtoField.uint32("CoAProtocol.Size1", "Size", base.DEC)
--END OF option fields for a "true" version of CoAP


--end of options, start of payload
local f_payload = ProtoField.string("CoAProtocol.payload", "Dummy data", base.HEX)

--local f_debug = ProtoField.uint8("CoAProtocol.debug", "Debug")
p_CoAProtocol.fields = {f_Ver, f_Type, f_TKL, f_Code, f_MsgID, f_Token, f_option1, f_option2, f_payload}

--FIELDS FOR A TRUE VERSION OF COAP:
    --p.CoAProtocol.fields = {f_Ver, f_Type, f_TKL, f_Code, f_MsgID, f_Token, f_option_if-match, f_option_Uri-Host, f_option_ETag, f_option_Uri-Port, f_option_Location-Path, f_option_Uri-Path, f_option_Content-Format, f_option_Max-Age, f_option_Uri-Query, f_option_Accept, f_option_Location-Query, f_option_Proxy-Uri, f_option_Proxy-Scheme, f_option_Size1}
--END OF FIELDS


-- Coap dissector function
function p_CoAProtocol.dissector (buf, pkt, root)
    if buf:len() == 0 then return end
    pkt.cols.protocol = p_CoAProtocol.name
    local offset = 0
    
    -- subtree for CoAProtocol
    subtree = root:add(p_CoAProtocol, buf(0))
    
    local firstByte = buf(offset, 1) --contains version, msg type and token length
    local Version, Type, TKL = bitstring.unpack("2:int, 2:int, 4:int", bitstring.fromhexstream(tostring(firstByte:bytes()))) --if Version, type and token length are needed later on
	subtree:add(f_Ver, firstByte)
	subtree:add(f_Type, firstByte)
	subtree:add(f_TKL, firstByte)
	offset = offset + 1
	
	
	local secondbyte = buf(offset,1) --contains code
	if secondbyte:len() ~= 0 then
	    subtree:add(f_Code, secondbyte)
	elseif secondbyte:len() == 0 then
	    subtree:add(f_Code, 0) --#fulhack, inga responsekoder på NON:s
	end
	offset = offset + 1
	
	
	local idbytes = buf(offset,2) --contains message id
	subtree:add(f_MsgID, idbytes)
	offset = offset + 2
	
	local tokenbytes = buf(offset, TKL) --contains token value
	subtree:add(f_Token, tokenbytes)
	offset = offset + TKL + 1 --after the token field, a byte 1111 1111 comes. The " + 1" takes care of that byte
	
	--all the option fields here; but how to dissect them?
	--IDEA: ....
	
	
	
	--IF THE MESSAGE IS AN ACK, the offset becomes larger than the offset. This causes an error. Fixed by adding options and payload only if buffer is greater than offset
	if buf:len() > offset then
		local firstoptionbytes = buf(offset, 2) --first option, destination port
	    subtree:add(f_option1, firstoptionbytes)
	    offset = offset + 2
	end
	
	if buf:len() > offset then
	    local secondoptionbytes = buf(offset, 5) --second option, point of transmission
	    subtree:add(f_option2, secondoptionbytes)
	    offset = offset + 5
	end
	--thoughts about optionbytes: with another field in header with info about options, the dissector could be made much more generic.
	
	if buf:len() > offset then
	    local yolo = buf:len()
	    local yoloswag = yolo-offset
	    --yoloswag is now number of bytes in payload
	    local payloadbytes = buf(offset, yoloswag) --payload
	    subtree:add(f_payload, payloadbytes)
	end
	
	--for debug uses
    if f_debug then
        subtree:add(f_debug, buf:len())
    end
end

function p_CoAProtocol.init()
end
--coap standard port is 5683
--we use ports 56830 and 46241
local udp_dissector_table = DissectorTable.get("udp.port")
dissector = udp_dissector_table:get_dissector(46241)
udp_dissector_table:add(46241, p_CoAProtocol)
udp_dissector_table:add(56830, p_CoAProtocol) -- this line might break program NOTE THIS
 


