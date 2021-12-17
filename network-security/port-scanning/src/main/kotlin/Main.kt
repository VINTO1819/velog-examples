import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.packet.*
import org.pcap4j.packet.namednumber.*
import org.pcap4j.util.MacAddress
import org.pcap4j.util.NifSelector
import java.net.Inet4Address

class PortScanning

fun main() {
    val nif = NifSelector().selectNetworkInterface() // 네트워크 인터페이스 선택

    val handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000) // 핸들러 생성

    val apMacAddress = MacAddress.getByName("") // 요청을 보낼 때 사용하는 공유기 MAC주소
    val myMacAddress = MacAddress.getByName("") // 요청의 회신을 받을 때 필요한 내 MAC주소

    print(" 내 IP를 입력해주세요 > ")
    val myIp = Inet4Address.getByName(readLine()) as Inet4Address

    print(" 대상 IP를 입력해주세요 > ")
    val targetIp = Inet4Address.getByName(readLine()) as Inet4Address // 타겟의 IP를 입력받음

    while(true) cmd(handle, apMacAddress, myMacAddress, myIp, targetIp)
}


enum class OpenState {
    OPEN, // 열린 포트
    CLOSED, // 닫힌 포트
    NOT_THIS_PACKET // 찾는 패킷이 아님
}

// 타임아웃 대비 패킷 수 카운터
var packetCount = 0

// 포트 입력받는 함수
fun cmd(handler: PcapHandle, apMacAddress : MacAddress, myMacAddress: MacAddress, myIp: Inet4Address, targetIp: Inet4Address) {
    print(" 대상 포트를 입력해주세요 > ")
    val port = readLine()!!.toShort()

    // SYN 요청을 위한 TCP 패킷 생성(전송 계층)
    val tcpSynPacket = TcpPacket.Builder()
        .syn(true) // flag를 SYN으로 설정
        .sequenceNumber((Math.random() * 100000000).toInt()) // 시퀀스 넘버는 랜덤으로
        .srcAddr(myIp).srcPort(TcpPort.getInstance((50000 + Math.random() * 9000).toInt().toShort())) // 공격자의 주소와 포트 설정
        .dstAddr(targetIp).dstPort(TcpPort.getInstance(port)) // 타겟의 주소와 포트 설정
        .correctChecksumAtBuild(true) // 체크섬 자동생성
        .correctLengthAtBuild(true) // 길이 자동설정
        .window(1024) // window size는 nmap과 동일하게 설정
        .paddingAtBuild(true) // padding 자동 설정
        .options(listOf( // 단편화 최대크기 설정(nmap과 동일하게 설정)
            TcpMaximumSegmentSizeOption.Builder().maxSegSize(1460).length(4).correctLengthAtBuild(true).build()
        ))

    // TCP 패킷 전송을 위한 IpV4 패킷 생성(네트워크 계층)
    val ipPacket = IpV4Packet.Builder()
        .identification((Math.random() * (Short.MAX_VALUE - 1)).toInt().toShort()) // 식별id 설정
        .dontFragmentFlag(true) // 단편화 미사용 플래그 설정
        .srcAddr(myIp) // 공격자 ip 설정
        .dstAddr(targetIp) // 타겟 ip 설정
        .payloadBuilder(tcpSynPacket) // TCP 패킷 포함
        .protocol(IpNumber.TCP) // 페이로드 프로토콜 설정(tcp)
        .version(IpVersion.IPV4) // ip 패킷 버전 설정(IPv4)
        .tos { IpV4TosTos.DEFAULT.value() } // tos(type of service)는 기본값으로 설정
        .ttl(128.toByte()) // TTL은 Windows 기본값
        .paddingAtBuild(true) // padding 자동 설정
        .correctLengthAtBuild(true) // 길이 자동설정
        .correctChecksumAtBuild(true) // 체크섬 자동생성

    // 라우터(공유기)에 전달을 위한 Ethernet 패킷 생성(데이터링크 계층)
    val ethPacket = EthernetPacket.Builder()
        .srcAddr(myMacAddress) // 공격자 주소 설정
        .dstAddr(apMacAddress) // 라우터(공유기) 주소 설정
        .type(EtherType.IPV4) // 페이로드 프로토콜 설정
        .payloadBuilder(ipPacket) // IPv4 패킷 포함
        .paddingAtBuild(true) // padding 자동 설정
        .build() // 패킷 빌드

    handler.sendPacket(ethPacket) // 패킷 전송

    var currentPacket = try { handler.nextPacket } catch (ex: Exception) { null } // 현재 패킷(nullable)
    while(true) { // 지속적으로 패킷 가져오기
        if(currentPacket != null) { // 패킷이 null이 아니라면
            packetCount++
            if(packetCount >= 1024) {
                println(" [${targetIp}:${port}] BLOCKED by firewall(or timeout)\n")
                return
            }

            val rslt = isOpen(currentPacket, targetIp, port)
            if(rslt != OpenState.NOT_THIS_PACKET) {
                println(" [${targetIp}:${port}] ${rslt.name}\n")
                packetCount = 0
                return
            }
        }

        currentPacket = handler.nextPacket
    }
}

fun isOpen(packet: Packet, targetIp: Inet4Address, targetPort: Short): OpenState {
    if(!packet.contains(TcpPacket::class.java)) return OpenState.NOT_THIS_PACKET // TCP 패킷이 아니면 리턴

    val ipPacket = packet.get(IpV4Packet::class.java)
    val tcpPacket = packet.get(TcpPacket::class.java)

    if(ipPacket.header.srcAddr != targetIp) return OpenState.NOT_THIS_PACKET
    if(tcpPacket.header.ack && tcpPacket.header.srcPort.value() == targetPort) { // ACK OOO이여야 여부 확인 가능
        return if(tcpPacket.header.syn) { // SYN-ACK
            OpenState.OPEN
        }else if(tcpPacket.header.rst) { // RST-ACK
            OpenState.CLOSED
        }else { // 기타 경우인 경우
            OpenState.NOT_THIS_PACKET
        }
    }else{
        return OpenState.NOT_THIS_PACKET
    }
}