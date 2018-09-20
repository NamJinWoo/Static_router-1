package Router;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class PacketDriverLayer extends BaseLayer {
   static {
      try {
         System.load(new File("jnetpcap.dll").getAbsolutePath());
         System.out.println(new File("jnetpcap.dll").getAbsolutePath());
      } catch (UnsatisfiedLinkError e) {
         System.out.println("Native code library failed to load.\n" + e);
         System.exit(1);
      }
   }

   int iNumberAdapter;
   public Pcap adapterObject;
   public PcapIf device;
   public ArrayList<PcapIf> adapterList;
   StringBuilder errorBuffer = new StringBuilder();
   long start;

   public PacketDriverLayer(String layerName) {
      super(layerName);

      adapterList = new ArrayList<PcapIf>();
      iNumberAdapter = 0;
      setAdapterList();

   }

   public void packetStartDriver() {
      int snaplength = 64 * 1024;
      int flags = Pcap.MODE_PROMISCUOUS;
      int timeout = 1 * 1000;

      adapterObject = Pcap.openLive(adapterList.get(iNumberAdapter).getName(), snaplength, flags, timeout,
            errorBuffer);

   }

   public void setAdapterNumber(int iNumber) {
      iNumberAdapter = iNumber;
      packetStartDriver();
      receive();
   }

   public void setAdapterList() {
         int r = Pcap.findAllDevs(adapterList, errorBuffer);

      if (r == Pcap.NOT_OK || adapterList.isEmpty())
         System.out.println("[Error] 네트워크 어댑터를 읽지 못하였습니다. Error : " + errorBuffer.toString());
   }

   public ArrayList<PcapIf> getAdapterList() {
      return adapterList;
   }

   boolean send(byte[] data, int length) {
      ByteBuffer buffer = ByteBuffer.wrap(data);
      start = System.currentTimeMillis();

      if (adapterObject.sendPacket(buffer) != Pcap.OK) {
         System.err.println(adapterObject.getErr());
         return false;
      }
      return true;
   }

   synchronized boolean receive() {
      Receive_Thread thread = new Receive_Thread(adapterObject, (EthernetLayer) this.getUpperLayer());
      Thread object = new Thread(thread);
      object.start();
      try {
         object.join(1);
      } catch (InterruptedException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      }

      return false;
   }

   String[] getNICDescription() {
      String[] descriptionArray = new String[adapterList.size()];

      for (int i = 0; i < adapterList.size(); i++)
         descriptionArray[i] = adapterList.get(i).getDescription();

      return descriptionArray;
   }
}

class Receive_Thread implements Runnable {
   byte[] data;
   Pcap adapterObejct;
   EthernetLayer upperLayer;

   public Receive_Thread(Pcap adapterObject, EthernetLayer upperLayer) {
      this.adapterObejct = adapterObject;
      this.upperLayer = upperLayer;
   }

   @Override
   public void run() {
      while (true) {
         PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
               data = packet.getByteArray(0, packet.size());
               if ((data[12] == 8 && data[13] == 0) || (data[12] == 8 && data[13] == 6))
                  upperLayer.receive(data);
            }
         };
         adapterObejct.loop(1000, packetHandler, "");
      }
   }
}