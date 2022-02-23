select
    bios.SerialNumber0 as DeviceSerialNumber,
    (os.SerialNumber0) as WindowsProductID,
    mdm.DeviceHardwareData0
from
    v_GS_PC_BIOS bios
    inner join v_GS_OPERATING_SYSTEM os on bios.ResourceID = os.ResourceID
    inner join v_GS_MDM_DEVDETAIL_EXT01 mdm on os.ResourceID = mdm.ResourceID
    inner join v_R_System sys on mdm.ResourceID = sys.ResourceID
	inner join v_FullCollectionMembership FCM on Sys.ResourceID = FCM.ResourceID 
    inner join v_Collection COL on FCM.CollectionID = COL.CollectionID 
where
	COL.Name = 'All Workstations'