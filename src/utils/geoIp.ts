import axios from 'axios';

export interface GeoIpData {
  country: string;
  countryCode: string;
  lat: number;
  lon: number;
  isp: string;
  query: string;
}

export async function getGeoIp(ip: string): Promise<GeoIpData | null> {
  try {
    const { data } = await axios.get<GeoIpData>(
      `http://ip-api.com/json/${ip}?fields=country,countryCode,lat,lon,isp,query`,
      { timeout: 3000 },
    );
    return data;
  } catch {
    return null;
  }
}
