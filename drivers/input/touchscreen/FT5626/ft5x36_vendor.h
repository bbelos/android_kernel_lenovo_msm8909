/*
 focaltelech tp firmware update infomations
 
 Date           Author       Module    vendor id    Old_ver    New_ver
 2015.01.19    pangle     toptouch     0xA0         null         0x0C
 2015.04.09    pangle     toptouch     0xA0         0x0C         0x0D
 2015.04.09    pangle     toptouch     0xA0         0x0D         0x0F
 2015.05.08    pangle     toptouch     0xA0         0x0F          0x10
 2015.05.08    pangle     toptouch     0xA0         0x10          0x11
 2015.06.26    pangle     toptouch     0xA0         0x11          0x14
 */
#ifndef __FOCALTECH_VENDOR_H__
#define __FOCALTECH_VENDOR_H__

#include "ft5x36_vendor_id.h"

//added by miaoxiliang for A6505 fw upgrade at 20160623 begin

static unsigned char FT5626_FIRMWARE0x59_LAIBAO[] = {

/*modified for  [SW00188085] by miaoxiliang 2016.7.7 begin*/
//#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x07_20160623_app.h"
//#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x09_20160706_app.h"
//#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x0A_20160707_app.h"
//#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x2F_20160708_app.h"
//#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x3F_20160708_app.h"
//#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x0B_20160708_app.h"
//#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x0D_20160726_app.h"
#include "ft5x36_firmware/A6505_LENOVO_FT5626_0x59_Ver0x0E_20160730_app.h"
/*modified for  [SW00188085] by miaoxiliang 2016.7.7 end*/
};

//added by miaoxiliang for A6505 fw upgrade at 20160623 end



#endif
